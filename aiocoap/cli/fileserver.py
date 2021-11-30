# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""A simple file server that serves the contents of a given directory in a
read-only fashion via CoAP. It provides directory listings, and guesses the
media type of files it serves."""

import argparse
import asyncio
from pathlib import Path
import logging
from stat import S_ISREG, S_ISDIR
import mimetypes

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

class FileServer(Resource, aiocoap.interfaces.ObservableResource):
    # Resource is only used to give the nice render_xxx methods

    def __init__(self, root, log):
        self.root = root
        self.log = log

        self._observations = {} # path -> [last_stat, [callbacks]]

    # While we don't have a .well-known/core resource that would need this, we
    # still allow registration at an RD and thus need something in here.
    #
    # As we can't possibly register all files in here, we're just registering a
    # single link to the index.
    def get_resources_as_linkheader(self):
        return '</>;ct=40'

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
        # Yes for directory listings, no for everything else
        return not request.opt.uri_path or request.opt.uri_path[-1] == ''

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

        if S_ISDIR(st.st_mode):
            return await self.render_get_dir(request, path)
        elif S_ISREG(st.st_mode):
            return await self.render_get_file(request, path)

    async def render_get_dir(self, request, path):
        if request.opt.uri_path and request.opt.uri_path[-1] != '':
            raise TrailingSlashMissingError()

        self.log.info("Serving directory %s", path)

        response = ""
        for f in path.iterdir():
            rel = f.relative_to(path)
            if f.is_dir():
                response += "<%s/>;ct=40,"%rel
            else:
                response += "<%s>,"%rel
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
        try:
            content_format = aiocoap.numbers.ContentFormat.by_media_type(guessed_type)
        except KeyError:
            if guessed_type and guessed_type.startswith('text/'):
                content_format = aiocoap.numbers.ContentFormat.TEXT
            else:
                content_format = aiocoap.numbers.ContentFormat.OCTETSTREAM
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
        p.add_argument("path", help="Root directory of the server", nargs="?", default=".", type=Path)

        add_server_arguments(p)

        return p

    async def start_with_options(self, path, verbosity=0, register=False,
            server_opts=None):
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

        server = FileServer(path, log)
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
