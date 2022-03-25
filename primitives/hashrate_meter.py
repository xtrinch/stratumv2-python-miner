"""
this class estimates miner speed from reported shares
implemented using rolling time window
the HashrateMeter.roll method is called automatically each 5 seconds by default (granularity = 5)
"""
import time

import numpy as np
import simpy


class HashrateMeter(object):
    def __init__(
        self,
        window_size: int = 60,
        granularity: int = 5,
        auto_hold_threshold=None,
    ):
        self.time_started = (
            self.get_time()
        )  # was originally zero, as simpy starts from 0
        self.window_size = window_size
        self.granularity = granularity
        self.pow_buffer = np.zeros(self.window_size // self.granularity)
        self.submit_buffer = np.zeros(self.window_size // self.granularity)
        self.frozen_time_buffer = np.zeros(self.window_size // self.granularity)
        self.roll_proc = None
        # self.roll_proc = env.process(self.roll())
        self.auto_hold_threshold = auto_hold_threshold
        self.on_hold = False
        self.put_on_hold_proc = None

    def get_time(self):
        return int(time.time())

    def reset(self, time_started):
        self.pow_buffer = np.zeros(self.window_size // self.granularity)
        self.submit_buffer = np.zeros(self.window_size // self.granularity)
        self.frozen_time_buffer = np.zeros(self.window_size // self.granularity)
        self.time_started = time_started
        if self.put_on_hold_proc:
            self.put_on_hold_proc.interrupt()  # terminate the current auto-on-hold process if exists

    def roll(self):
        while True:
            try:
                yield self.env.timeout(self.granularity)
                if not self.on_hold:
                    self.pow_buffer = np.roll(self.pow_buffer, 1)
                    self.pow_buffer[0] = 0
                    self.submit_buffer = np.roll(self.submit_buffer, 1)
                    self.submit_buffer[0] = 0
                    self.frozen_time_buffer = np.roll(self.frozen_time_buffer, 1)
                    self.frozen_time_buffer[0] = 0
                else:
                    self.frozen_time_buffer[0] += self.granularity
            except simpy.Interrupt:
                break

    def on_hold_after_timeout(self):
        try:
            yield self.env.timeout(self.auto_hold_threshold)
            self.on_hold = True
            self.put_on_hold_proc = None
        except simpy.Interrupt:
            pass  # do nothing

    def measure(self, share_diff: int):
        """Account for the shares

        TODO: consider changing the interface to accept the difficulty target directly
        """
        self.pow_buffer[0] += share_diff
        self.submit_buffer[0] += 1
        self.on_hold = False  # reset frozen status whenever a share is submitted
        if self.auto_hold_threshold:
            if self.put_on_hold_proc:
                self.put_on_hold_proc.interrupt()  # terminate the current auto-on-hold process if exists
            self.put_on_hold_proc = self.env.process(
                self.on_hold_after_timeout()
            )  # will trigger after the threshold

    def get_speed(self):
        total_time_held = np.sum(self.frozen_time_buffer)
        time_elapsed = self.get_time() - self.time_started - total_time_held
        if time_elapsed > self.window_size:
            time_elapsed = self.window_size
        total_work = np.sum(self.pow_buffer)
        if time_elapsed < 1 or total_work == 0:
            return None

        return total_work * 4.294967296 / time_elapsed

        # time_elapsed = self.env.now - self.time_started - total_time_held
        # if time_elapsed > self.window_size:
        #     time_elapsed = self.window_size
        # total_work = np.sum(self.pow_buffer)
        # if time_elapsed < 1 or total_work == 0:
        #     return None

        # return total_work * 4.294967296 / time_elapsed

    def get_submit_per_secs(self):
        total_time_held = np.sum(self.frozen_time_buffer)
        time_elapsed = self.env.now - self.time_started - total_time_held
        if time_elapsed < 1:
            return None
        elif time_elapsed > self.window_size:
            time_elapsed = self.window_size
        return np.sum(self.submit_buffer) / time_elapsed

    def is_on_hold(self):
        return self.on_hold

    def terminate(self):
        self.roll_proc.interrupt()
        if self.put_on_hold_proc:
            self.put_on_hold_proc.interrupt()  # terminate the current auto-on-hold process if exists
