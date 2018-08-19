import struct


# ported from the eosio codebase, libraries/chain/include/eosio/chain/name.hpp
def char_to_symbol(c):
    if (ord(c) >= ord('a') and ord(c) <= ord('z')):
        return ord(c) - ord('a') + 6

    if (ord(c) >= ord('1') and ord(c) <= ord('5')):
        return ord(c) - ord('1') + 1
    return 0


def string_to_name(string):
    v = 0
    c = 0
    for i in range(13):
        if i < len(string):
            c = char_to_symbol(string[i])
        if i < 12:
            c &= 0x1f
            c <<= 64 - 5 * (i + 1)
        else:
            c &= 0x0f
        v |= c
    return v


def write_string(v):
    length = len(v)
    length >>= 0
    a = b''
    while length >= 0x80:
        b = (length & 0x7f) | 0x80
        a += bytes([b])
        length >>= 7

    a += bytes([length])
    a += v
    return a


def abi_json_to_bin(send_account, recv_account, send_amount, memo, code, unit):
    data = b''
    val = string_to_name(send_account)
    data += struct.pack('<Q', val)
    val = string_to_name(recv_account)
    data += struct.pack('<Q', val)
    data += struct.pack('<Q', int(float(send_amount) * 10000))
    val = b'\x04' + unit.encode('unicode_escape')
    data += val
    data += bytes([0 for n in range(8 - len(val))])
    val = write_string(memo.encode('unicode_escape'))
    data += val
    return data

def int_to_bytes(x):
    return struct.pack("<I", x)
    #return x.to_bytes((x.bit_length() + 7) // 8, 'little')

def int_from_bytes(xbytes):
    #return struct.unpack("<I", xbytes)[0]
    return int.from_bytes(xbytes, 'little')
