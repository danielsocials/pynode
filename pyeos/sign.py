import base58
import pkg_resources
from secp256k1 import PrivateKey, PublicKey, ECDSA
import hashlib
from Crypto.Hash import SHA256
from Crypto.Hash import RIPEMD

def get_private_ket_by_wif(wif):
    data = bytearray(base58.b58decode(wif))
    if data[0] != 0x80:
        raise 'Wrong private key'
    return  data[1:33]

def sign(wfi, trx, raw=True):
    pri = get_private_ket_by_wif(wfi)

    if not raw:
        trx = hashlib.sha256(trx).digest()

    privkey = PrivateKey(bytes(pri), raw=True)

    count = 0
    i = 0
    for j in range(0, 10, 1):
        count += 1
        sig2, rec_id = privkey.ecdsa_sign(trx, raw=True, count=count)
        dsig = privkey.ecdsa_serialize(sig2)

        lenR = dsig[3]
        lenS = dsig[5 + lenR]

        if (lenR == 32 and lenS == 32):
            i = rec_id[0]
            i += 4;  # compressed
            i += 27; # compact  //  24 or 27 :( forcing odd-y 2nd key candidate)
            break

    R = dsig[4:36]
    S = dsig[38:]
    data  = bytes([i]) + R + S + b'K1'
    h = RIPEMD.new()
    h.update(data)
    p=h.digest()
    checksum = p[0:4]
    data =  bytes([i]) + R + S + checksum 
    return "SIG_K1_" + base58.b58encode(data)
 

def get_pubkey(wfi):
    pri = get_private_ket_by_wif(wfi)
    privkey = PrivateKey(bytes(pri), raw=True)
    pubkey = privkey.pubkey.serialize()

    h = RIPEMD.new()
    h.update(pubkey)
    p=h.digest()
    checksum = p[0:4]

    return "EOS" + base58.b58encode(pubkey + checksum)
