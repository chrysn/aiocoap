# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""A simple file server that serves the contents of a given directory in a
read-only fashion via CoAP. It provides directory listings, and guesses the
media type of files it serves.

It follows the conventions set out for the [kitchen-sink fileserver],
optionally with write support, with some caveats:

* There are some time-of-check / time-of-use race conditions around the
  handling of ETags, which could probably only be resolved if heavy file system
  locking were used. Some of these races are a consequence of this server
  implementing atomic writes through renames.

  As long as no other processes access the working area, and aiocoap is run
  single threaded, the races should not be visible to CoAP users.

* ETags are constructed based on information in the file's (or directory's)
  `stat` output -- this avoids reaing the whole file on overwrites etc.

  This means that forcing the MTime to stay constant across a change would
  confuse clients.

* While GET requests on files are served block by block (reading only what is
  being requested), PUT operations are spooled in memory rather than on the
  file system.

* Directory creation and deletion is not supported at the moment.

[kitchen-sink fileserver]: https://www.ietf.org/archive/id/draft-amsuess-core-coap-kitchensink-00.html#name-coap
"""

import argparse
import asyncio
from pathlib import Path
import logging
from stat import S_ISREG, S_ISDIR
import mimetypes
import tempfile
import hashlib

import aiocoap
import aiocoap.error as error
import aiocoap.numbers.codes as codes
from aiocoap.resource import Resource
from aiocoap.util.cli import AsyncCLIDaemon
from aiocoap.cli.common import (add_server_arguments,
    server_context_from_arguments, extract_server_arguments)
from aiocoap.resourcedirectory.client.register import Registerer
from ..util.asyncio import py38args

class InvalidPathError(error.ConstructionRenderableError):
    code = codes.BAD_REQUEST

class TrailingSlashMissingError(error.ConstructionRenderableError):
    code = codes.BAD_REQUEST
    message = "Error: Not a file (add trailing slash)"

class AbundantTrailingSlashError(error.ConstructionRenderableError):
    code = codes.BAD_REQUEST
    message = "Error: Not a directory (strip the trailing slash)"

class NoSuchFile(error.NotFound): # just for the better error msg
    message = "Error: File not found!"

class PreconditionFailed(error.ConstructionRenderableError):
    code = codes.PRECONDITION_FAILED

class FileServer(Resource, aiocoap.interfaces.ObservableResource):
    # Resource is only used to give the nice render_xxx methods

    def __init__(self, root, log, *, write=False):
        super().__init__()
        self.root = root
        self.log = log
        self.write = write

        self._observations = {} # path -> [last_stat, [callbacks]]

    # While we don't have a .well-known/core resource that would need this, we
    # still allow registration at an RD and thus need something in here.
    #
    # As we can't possibly register all files in here, we're just registering a
    # single link to the index.
    def get_resources_as_linkheader(self):
        # Resource type indicates draft-amsuess-core-coap-kitchensink-00 file
        # service, might use registered name later
        return '</>;ct=40;rt="tag:chrysn@fsfe.org,2022:fileserver"'

    async def check_files_for_refreshes(self):
        while True:
            await asyncio.sleep(10)

            for path, data in list(self._observations.items()):
                last_stat, callbacks = data
                if last_stat is None:
                    continue # this hit before the original response even triggered
                try:
                    new_stat = path.stat()
                except Exception:
                    new_stat = False
                def relevant(s):
                    return (s.st_ino, s.st_dev, s.st_size, s.st_mtime, s.st_ctime)
                if relevant(new_stat) != relevant(last_stat):
                    self.log.info("New stat for %s", path)
                    data[0] = new_stat
                    for cb in callbacks:
                        cb()

    def request_to_localpath(self, request):
        path = request.opt.uri_path
        if any('/' in p or p in ('.', '..') for p in path):
            raise InvalidPathError()

        return self.root / "/".join(path)

    async def needs_blockwise_assembly(self, request):
        if request.code != codes.GET:
            return True
        if not request.opt.uri_path or request.opt.uri_path[-1] == '' or \
                request.opt.uri_path == ('.well-known', 'core'):
            return True
        # Only GETs to non-directory access handle it explicitly
        return False

    @staticmethod
    def hash_stat(stat):
        # The subset that the author expects to (possibly) change if the file changes
        data = (stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size)
        return hashlib.sha256(repr(data).encode('ascii')).digest()[:8]

    async def render_get(self, request):
        if request.opt.uri_path == ('.well-known', 'core'):
            return aiocoap.Message(
                    payload=str(self.get_resources_as_linkheader()).encode('utf8'),
                    content_format=40
                    )

        path = self.request_to_localpath(request)
        try:
            st = path.stat()
        except FileNotFoundError:
            raise NoSuchFile()

        etag = self.hash_stat(st)

        if etag in request.opt.etags:
            response = aiocoap.Message(code=codes.VALID)
        else:
            if S_ISDIR(st.st_mode):
                response = await self.render_get_dir(request, path)
            elif S_ISREG(st.st_mode):
                response = await self.render_get_file(request, path)

        response.opt.etag = etag
        return response

    async def render_put(self, request):
        if not self.write:
            return aiocoap.Message(code=codes.FORBIDDEN)

        if not request.opt.uri_path or not request.opt.uri_path[-1]:
            # Attempting to write to a directory
            return aiocoap.Message(code=codes.BAD_REQUEST)

        path = self.request_to_localpath(request)

        if request.opt.if_none_match:
            # FIXME: This is locally a race condition; files could be created
            # in the "x" mode, but then how would writes to them be made
            # atomic?
            if path.exists():
                raise PreconditionFailed()

        if request.opt.if_match and b"" not in request.opt.if_match:
            # FIXME: This is locally a race condition; not sure how to prevent
            # that.
            try:
                st = path.stat()
            except FileNotFoundError:
                # Absent file in particular doesn't have the expected ETag
                raise PreconditionFailed()
            if self.hash_stat(st) not in request.opt.if_match:
                raise PreconditionFailed()

        # Is there a way to get both "Use umask for file creation (or the
        # existing file's permissions)" logic *and* atomic file creation on
        # portable UNIX? If not, all we could do would be emulate the logic of
        # just opening the file (by interpreting umask and the existing file's
        # permissions), and that fails horrobly if there are ACLs in place that
        # bites rsync in https://bugzilla.samba.org/show_bug.cgi?id=9377.
        #
        # If there is not, secure temporary file creation is as good as
        # anything else.
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as spool:
            spool.write(request.payload)
            temppath = Path(spool.name)
        try:
            temppath.rename(path)
        except Exception:
            temppath.unlink()
            raise

        st = path.stat()
        etag = self.hash_stat(st)

        return aiocoap.Message(code=codes.CHANGED, etag=etag)

    async def render_delete(self, request):
        if not self.write:
            return aiocoap.Message(code=codes.FORBIDDEN)

        if not request.opt.uri_path or not request.opt.uri_path[-1]:
            # Deleting directories is not supported as they can't be created
            return aiocoap.Message(code=codes.BAD_REQUEST)

        path = self.request_to_localpath(request)

        if request.opt.if_match and b"" not in request.opt.if_match:
            # FIXME: This is locally a race condition; not sure how to prevent
            # that.
            try:
                st = path.stat()
            except FileNotFoundError:
                # Absent file in particular doesn't have the expected ETag
                raise NoSuchFile()
            if self.hash_stat(st) not in request.opt.if_match:
                raise PreconditionFailed()

        try:
            path.unlink()
        except FileNotFoundError:
            raise NoSuchFile()

        return aiocoap.Message(code=codes.DELETED)

    async def render_get_dir(self, request, path):
        if request.opt.uri_path and request.opt.uri_path[-1] != '':
            raise TrailingSlashMissingError()

        self.log.info("Serving directory %s", path)

        response = ""
        for f in path.iterdir():
            rel = f.relative_to(self.root)
            if f.is_dir():
                response += "</%s/>;ct=40," % rel
            else:
                response += "</%s>," % rel
        return aiocoap.Message(payload=response[:-1].encode('utf8'), content_format=40)

    async def render_get_file(self, request, path):
        if request.opt.uri_path and request.opt.uri_path[-1] == '':
            raise AbundantTrailingSlashError()

        self.log.info("Serving file %s", path)

        block_in = request.opt.block2 or aiocoap.optiontypes.BlockOption.BlockwiseTuple(0, 0, 6)

        with path.open('rb') as f:
            f.seek(block_in.start)
            data = f.read(block_in.size + 1)

        if path in self._observations and self._observations[path][0] is None:
            # FIXME this is not *completely* precise, as it might mean that in
            # a (Observation 1 established, check loop run, file modified,
            # observation 2 established) situation, observation 2 could receive
            # a needless update on the next check, but it's simple and errs on
            # the side of caution.
            self._observations[path][0] = path.stat()

        guessed_type, _ = mimetypes.guess_type(str(path))

        block_out = aiocoap.optiontypes.BlockOption.BlockwiseTuple(block_in.block_number, len(data) > block_in.size, block_in.size_exponent)
        content_format = None
        if guessed_type is not None:
            try:
                content_format = aiocoap.numbers.ContentFormat.by_media_type(guessed_type)
            except KeyError:
                if guessed_type and guessed_type.startswith('text/'):
                    content_format = aiocoap.numbers.ContentFormat.TEXT
        return aiocoap.Message(
                payload=data[:block_in.size],
                block2=block_out,
                content_format=content_format,
                observe=request.opt.observe
                )

    async def add_observation(self, request, serverobservation):
        path = self.request_to_localpath(request)

        # the actual observable flag will only be set on files anyway, the
        # library will cancel the file observation accordingly if the requested
        # thing is not actually a file -- so it can be done unconditionally here

        last_stat, callbacks = self._observations.setdefault(path, [None, []])
        cb = serverobservation.trigger
        callbacks.append(cb)
        serverobservation.accept(lambda self=self, path=path, cb=cb: self._observations[path][1].remove(cb))

class FileServerProgram(AsyncCLIDaemon):
    async def start(self):
        logging.basicConfig()

        self.registerer = None

        p = self.build_parser()

        opts = p.parse_args()
        server_opts = extract_server_arguments(opts)

        await self.start_with_options(**vars(opts), server_opts=server_opts)

    @staticmethod
    def build_parser():
        p = argparse.ArgumentParser(description=__doc__)
        p.add_argument("-v", "--verbose", help="Be more verbose (repeat to debug)", action='count', dest="verbosity", default=0)
        p.add_argument("--register", help="Register with a Resource directory", metavar='RD-URI', nargs='?', default=False)
        p.add_argument("--write", help="Allow writes by any user", action='store_true')
        p.add_argument("path", help="Root directory of the server", nargs="?", default=".", type=Path)

        add_server_arguments(p)

        return p

    async def start_with_options(self, path, verbosity=0, register=False,
            server_opts=None, write=False):
        log = logging.getLogger('fileserver')
        coaplog = logging.getLogger('coap-server')

        if verbosity == 1:
            log.setLevel(logging.INFO)
        elif verbosity == 2:
            log.setLevel(logging.DEBUG)
            coaplog.setLevel(logging.INFO)
        elif verbosity >= 3:
            log.setLevel(logging.DEBUG)
            coaplog.setLevel(logging.DEBUG)

        server = FileServer(path, log, write=write)
        if server_opts is None:
            self.context = await aiocoap.Context.create_server_context(server)
        else:
            self.context = await server_context_from_arguments(server, server_opts)

        self.refreshes = asyncio.create_task(
                server.check_files_for_refreshes(),
                **py38args(name="Refresh on %r" % (path,))
                )

        if register is not False:
            if register is not None and register.count('/') != 2:
                log.warn("Resource directory does not look like a host-only CoAP URI")

            self.registerer = Registerer(self.context, rd=register, lt=60)

            if verbosity == 2:
                self.registerer.log.setLevel(logging.INFO)
            elif verbosity >= 3:
                self.registerer.log.setLevel(logging.DEBUG)

    async def shutdown(self):
        if self.registerer is not None:
            await self.registerer.shutdown()
        self.refreshes.cancel()
        await self.context.shutdown()

# used by doc/aiocoap_index.py
build_parser = FileServerProgram.build_parser

if __name__ == "__main__":
    FileServerProgram.sync_main()
