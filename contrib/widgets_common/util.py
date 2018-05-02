import time

class _Throttler:
    """Wrapper around an argumentless function that silently drops calls if
    there are too many."""
    # FIXME i'd rather have the ObservableResource or even the observation
    # itself handle this
    def __init__(self, callback):
        self.callback = callback
        self.last = 0

    def __call__(self):
        now = time.time()
        if now - self.last < 0.2:
            return
        self.last = now
        self.callback()
