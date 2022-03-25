import array
import binascii
import ctypes
import struct


def BOOL(bool):

    if bool:
        bool = True
    else:
        bool = False

    s = struct.Struct("<" + " ?")
    b = ctypes.create_string_buffer(1)
    s.pack_into(b, 0, bool)

    return b.raw


def U8(inter):

    assert type(inter) is int, "U8: not integer"

    if inter >= 2 ** 8:
        raise Exception("Overflow")

    return (inter).to_bytes(1, byteorder="little")


def U16(inter):

    assert type(inter) is int, "U16: not integer"

    if inter >= 2 ** 16:
        raise Exception("Overflow")

    return (inter).to_bytes(2, byteorder="little")


def U24(inter):

    assert type(inter) is int, "U24: not integer"

    if inter >= 2 ** 24:
        raise Exception("Overflow")

    return (inter).to_bytes(3, byteorder="little")


def U32(inter):
    assert type(inter) is int, "U32: not integer"

    if inter >= 2 ** 32:
        raise Exception("Overflow")

    return (inter).to_bytes(4, byteorder="little")


def F32(inter):

    assert type(inter) is float, "F32: not float"

    # little endian
    return struct.pack("<f", inter)


def U64(inter):

    assert type(inter) is int, "U64: not integer"

    if inter >= 2 ** 64:
        raise Exception("Overflow")

    return (inter).to_bytes(8, byteorder="little")


def U256(inter):
    if type(inter) is bytes:
        return inter

    assert type(inter) is int, "U256: not integer"

    if inter >= 2 ** 256:
        raise Exception("Overflow")

    return (inter).to_bytes(32, byteorder="little")


def STR0_255(string):

    assert type(string) is str, "STR0_255: not string"

    length = string.__len__()

    if length not in range(0, 2 ** 8):
        raise Exception("Overflow")

    s = struct.Struct("<" + " " + str(length) + "s")

    b = ctypes.create_string_buffer(length)

    s.pack_into(b, 0, string.encode("utf-8"))

    return U8(length) + b.raw


def B0_32(_bytes):
    assert type(_bytes) is bytes, "B0_32: not bytes"
    length = _bytes.__len__()
    if length not in range(0, 2 ** 8):
        raise Exception("Overflow")

    return U8(length) + _bytes


def B0_255(_bytes):
    assert type(_bytes) is bytes, "B0_255: not bytes"

    length = _bytes.__len__()

    if length not in range(0, 2 ** 8):
        raise Exception("Overflow")

    return U8(length) + _bytes


def B0_64K(_bytes):
    assert type(_bytes) is bytes, "B0_64K: not bytes"

    length = _bytes.__len__()

    if length not in range(0, 2 ** 16):
        raise Exception("Overflow")

    return U16(length) + _bytes


def B0_16M(_bytes):
    assert type(_bytes) is bytes, "B0_16M: not bytes"

    length = _bytes.__len__()

    if length not in range(0, 2 ** 24):
        raise Exception("Overflow")

    return U24(length) + _bytes


def BYTES(_bytes):
    assert type(_bytes) is bytes, "BYTES: not bytes"

    return _bytes


def PUBKEY(pubKey):
    return


def SEQ0_255():
    return


def SEQ0_64K():
    return


"""def msgTypesConverter(message_type,channel_msg_bit):
    #just to make the task easier (copy from spec)

    assert (channel_msg_bit==0 or channel_msg_bit==1)
    if channel_msg_bit == 1:
        channel_msg_bit = 0b10000000

    result = message_type | channel_msg_bit

    return result"""


def FRAME(extension_type, msg_type_name, payload):

    msg_type_list = {
        "SetupConnection": [0x00, 0],
        "SetupConnectionSuccess": [0x01, 0],
        "SetupConnectionError": [0x02, 0],
        "ChannelEndpointChanged": [0x03, 1],
        "OpenStandardMiningChannel": [0x10, 0],
        "OpenStandardMiningChannelSuccess": [0x11, 0],
        "OpenStandardMiningChannelError": [0x12, 0],
        "OpenExtendedMiningChannel": [0x13, 0],
        "OpenExtendedMiningChannelSuccess": [0x14, 0],
        "OpenExtendedMiningChannelError": [0x15, 0],
        "UpdateChannel": [0x16, 1],
        "UpdateChannelError": [0x17, 1],
        "CloseChannel": [0x18, 1],
        "SetExtranoncePrefix": [0x19, 1],
        "SubmitSharesStandard": [0x1A, 1],
        "SubmitSharesExtended": [0x1B, 1],
        "SubmitSharesSuccess": [0x1C, 1],
        "SubmitSharesError": [0x1D, 1],
        "NewMiningJob": [0x1E, 1],
        "NewExtendedMiningJob": [0x1F, 1],
        "SetNewPrevHash": [0x20, 1],
        "SetTarget": [0x21, 1],
        "SetCustomMiningJob": [0x22, 0],
        "SetCustomMiningJobSuccess": [0x23, 0],
        "SetCustomMiningJobError": [0x24, 0],
        "Reconnect": [0x25, 0],
        "SetGroupChannel": [0x26, 0],
        "AllocateMiningJobToken": [0x50, 0],
        "AllocateMiningJobTokenSuccess": [0x51, 0],
        "AllocateMiningJobTokenError": [0x52, 0],
        "IdentifyTransactions": [0x53, 0],
        "IdentifyTransactionsSuccess": [0x54, 0],
        "ProvideMissingTransactions": [0x55, 0],
        "ProvideMissingTransactionsSuccess": [0x56, 0],
        "CoinbaseOutputDataSize": [0x70, 0],
        "NewTemplate": [0x71, 0],
        "SetNewPrevHashTDP": [0x72, 0],
        "RequestTransactionData": [0x73, 0],
        "RequestTransactionDataSuccess": [0x74, 0],
        "RequestTransactionDataError": [0x75, 0],
        "SubmitSolution": [0x76, 0],
    }
    msg_type_pair = msg_type_list[msg_type_name]

    msg_type = msg_type_pair[0]  # msgTypesConverter(msg_type_pair[0],msg_type_pair[1])

    extension_type = extension_type

    channel_msg_bit = msg_type_pair[1]

    assert channel_msg_bit == 0 or channel_msg_bit == 1
    if channel_msg_bit == 1:
        channel_msg_bit = 0b10000000

    extension_type = extension_type | channel_msg_bit

    msg_length = payload.__len__()

    return U16(extension_type) + U8(msg_type) + U24(msg_length) + BYTES(payload)


def parse_bytes_to_int(frame, *args):

    # if just une argument, take the byte or bytes
    # if 2 arguments, first is the start and second is the end

    if len(args) == 1:
        end = args[0]
        start = args[0]
    elif len(args) == 2:
        start = args[0]
        end = args[1]
    else:
        start = 0
        end = frame.__len__()
        # raise Exception("Missing Arguments")

    data = int.from_bytes(frame[start:end], byteorder="little")
    return data
