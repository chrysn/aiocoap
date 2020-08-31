# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""Common code for the tcp and the ws modules, both of which are based on
RFC8323 mechanisms, but differ in their underlying protocol implementations
(asyncio stream vs. websockets module) far enough that they only share small
portions of their code"""

from typing import Optional
from aiocoap import Message
from aiocoap import optiontypes, util
from aiocoap.numbers.codes import CSM, PING, PONG, RELEASE, ABORT

class RFC8323Remote:
    """Mixin for Remotes for all the common RFC8323 processing

    Implementations still need the per-transport parts, especially a
    _send_message and an _abort_with implementation.
    """

    # CSM received from the peer. The receive hook should abort suitably when
    # receiving a non-CSM message and this is not set yet.
    # Python 3.7 hint
    #_remote_settings: Optional[Message]

    # Parameter usually set statically per implementation
    _my_max_message_size = 1024 * 1024

    def __init__(self):
        self._remote_settings = None

    is_multicast = False
    is_multicast_locally = False

    # implementing interfaces.EndpointAddress

    def __repr__(self):
        return "<%s at %#x, hostinfo %s, local %s>" % (type(self).__name__, id(self), self.hostinfo, self.hostinfo_local)

    @property
    def hostinfo(self):
        # keeping _remote_hostinfo and _local_hostinfo around structurally rather than in
        # hostinfo / hostinfo_local form looks odd now, but on the long run the
        # remote should be able to tell the message what its default Uri-Host
        # value is
        return util.hostportjoin(*self._remote_hostinfo)

    @property
    def hostinfo_local(self):
        return util.hostportjoin(*self._local_hostinfo)

    @property
    def uri_base(self):
        if self._is_server:
            raise error.AnonymousHost("Client side of %s can not be expressed as a URI" % self._ctx._scheme)
        else:
            return self._ctx._scheme + '://' + self.hostinfo

    @property
    def uri_base_local(self):
        if self._is_server:
            return self._ctx._scheme + '://' + self.hostinfo_local
        else:
            raise error.AnonymousHost("Client side of %s can not be expressed as a URI" % self._ctx._scheme)

    @property
    def maximum_block_size_exp(self):
        if self._remote_settings is None:
            # This is assuming that we can do BERT, so a first Block1 would be
            # exponent 7 but still only 1k -- because by the time we send this,
            # we typically haven't seen a CSM yet, so we'd be stuck with 6
            # because 7959 says we can't increase the exponent...
            #
            # FIXME: test whether we're properly using lower block sizes if
            # server says that szx=7 is not OK.
            return 7

        max_message_size = (self._remote_settings or {}).get('max-message-size', 1152)
        has_blockwise = (self._remote_settings or {}).get('block-wise-transfer', False)
        if max_message_size > 1152 and has_blockwise:
            return 7
        return 6 # FIXME: deal with smaller max-message-size

    @property
    def maximum_payload_size(self):
        max_message_size = (self._remote_settings or {}).get('max-message-size', 1152)
        has_blockwise = (self._remote_settings or {}).get('block-wise-transfer', False)
        if max_message_size > 1152 and has_blockwise:
            return ((max_message_size - 128) // 1024) * 1024
        return 1024 # FIXME: deal with smaller max-message-size

    # Utility methods for implementing an RFC8323 transport

    def _send_initial_csm(self):
        my_csm = Message(code=CSM)
        # this is a tad awkward in construction because the options objects
        # were designed under the assumption that the option space is constant
        # for all message codes.
        block_length = optiontypes.UintOption(2, self._my_max_message_size)
        my_csm.opt.add_option(block_length)
        supports_block = optiontypes.UintOption(4, 0)
        my_csm.opt.add_option(supports_block)
        self._send_message(my_csm)

    def _process_signaling(self, msg):
        if msg.code == CSM:
            if self._remote_settings is None:
                self._remote_settings = {}
            for opt in msg.opt.option_list():
                # FIXME: this relies on the relevant option numbers to be
                # opaque; message parsing should already use the appropriate
                # option types, or re-think the way options are parsed
                if opt.number == 2:
                    self._remote_settings['max-message-size'] = int.from_bytes(opt.value, 'big')
                elif opt.number == 4:
                    self._remote_settings['block-wise-transfer'] = True
                elif opt.number.is_critical():
                    self.abort("Option not supported", bad_csm_option=opt.number)
                else:
                    pass # ignoring elective CSM options
        elif msg.code in (PING, PONG, RELEASE, ABORT):
            # not expecting data in any of them as long as Custody is not implemented
            for opt in msg.opt.option_list():
                if opt.number.is_critical():
                    self.abort("Unknown critical option")
                else:
                    pass

            if msg.code == PING:
                pong = Message(code=PONG, token=msg.token)
                self._send_message(pong)
            elif msg.code == PONG:
                pass
            elif msg.code == RELEASE:
                raise NotImplementedError
            elif msg.code == ABORT:
                raise NotImplementedError
        else:
            self.abort("Unknown signalling code")

    def abort(self, errormessage=None, bad_csm_option=None):
        self.log.warning("Aborting connection: %s", errormessage)
        abort_msg = Message(code=ABORT)
        if errormessage is not None:
            abort_msg.payload = errormessage.encode('utf8')
        if bad_csm_option is not None:
            bad_csm_option_option = optiontypes.UintOption(2, bad_csm_option)
            abort_msg.opt.add_option(bad_csm_option_option)
        self._abort_with(abort_msg)
