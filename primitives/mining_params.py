"""This module gathers mining parameters"""
# this is a bitcoin constant, maximum possible target, 00000000ffff0000000000000000000000000000000000000000000000000000
# (0xFFFF << 208).to_bytes(32, byteorder="big").hex()
# larger target means lower difficulty, so this is the lowest possible target!
diff_1_target = 0xFFFF << 208
