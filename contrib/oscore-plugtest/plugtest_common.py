import shutil
from pathlib import Path

import cbor2 as cbor

from aiocoap import oscore

contextdir = Path(__file__).parent / 'common-context'

class LoggingFilesystemSecurityContext(oscore.FilesystemSecurityContext):
    def _extract_external_aad(self, message, request_id):
        result = super()._extract_external_aad(message, request_id)
        print("Verify: External AAD: bytes.fromhex(%r), %r"%(result.hex(), cbor.loads(result)))
        return result

class NotifyingPlugtestSecurityContext(oscore.FilesystemSecurityContext):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.notification_hooks = []

    def notify(self):
        for x in self.notification_hooks:
            x()

    def post_seqnoincrease(self):
        super().post_seqnoincrease()
        self.notify()

    def _replay_window_changed(self):
        super()._replay_window_changed()
        self.notify()

class PlugtestFilesystemSecurityContext(LoggingFilesystemSecurityContext, NotifyingPlugtestSecurityContext):
    pass

def get_security_context(contextname, contextcopy: Path, simulate_unclean_shutdown=False):
    """Copy the base context (disambiguated by contextname in "ab", "cd") onto
    the path in contextcopy if it does not already exist, and load the
    resulting context with the given role. The context will be monkey-patched
    for debugging purposes.

    With the simulate_unclean_shutdown aprameter set to True, any existing
    replay window is removed from the loaded state."""
    if not contextcopy.exists():
        contextcopy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree((contextdir / contextname), contextcopy)

        print("Context %s copied to %s" % (contextname, contextcopy))

    secctx = PlugtestFilesystemSecurityContext(contextcopy)

    if simulate_unclean_shutdown:
        secctx.recipient_replay_window._index = None
        secctx.recipient_replay_window._bitfield = None

    return secctx

def additional_verify(description, lhs, rhs):
    if lhs == rhs:
        print("Additional verify passed: %s"%description)
    else:
        print("Additional verify failed (%s != %s): %s"%(lhs, rhs, description))
