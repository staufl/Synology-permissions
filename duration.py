import math
import time

class Duration:
    """
    Context manager class designed to keep track of 
    how long an operation takes

    """

    default_round_ndigits = None

    def __init__(self, round_ndigits=None):
        self.start = self.duration = 0
        self.exit_called = False
        self.round_ndigits = round_ndigits or self.default_round_ndigits

    def __enter__(self):
        self.start = time.time()
        return self

    def __float__(self):
        self._update_duration()
        return self.duration

    def __str__(self, spec):
        self._update_duration()
        return str(self.duration)

    def __format__(self, spec):
        self._update_duration()
        return format(self.duration, spec)

    def __exit__(self, type_, value, traceback):
        self._update_duration()
        self.exit_called = True

        if traceback is not None:
            print("Unable to calculate Duration due to a crash")

        return traceback is None

    def _update_duration(self):
        if self.exit_called:
            return
        self.duration = time.time() - self.start

        if self.round_ndigits:
            self.duration = round(self.duration, self.round_ndigits)
