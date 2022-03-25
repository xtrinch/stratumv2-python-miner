"""Helper module with generic coin algorithms"""


class Target:
    def __init__(self, target: int, diff_1_target: int):
        self.target = target
        self.diff_1_target = diff_1_target

    def to_difficulty(self):
        """Converts target to difficulty at the network specified by diff_1_target"""
        return self.diff_1_target // self.target

    @staticmethod
    def from_difficulty(diff, diff_1_target):

        """Converts difficulty to target at the network specified by diff_1_target"""
        return Target(diff_1_target // diff, diff_1_target)

    def div_by_factor(self, factor: float):
        self.target = self.target // factor

    def __str__(self):
        return "{}(diff={}, target={})".format(
            type(self).__name__,
            self.to_difficulty(),
            self.target.to_bytes(32, byteorder="big").hex(),
        )

    def to_bytes(self):
        # TODO: convert to bytes
        return 1
