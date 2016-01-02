#!/usr/bin/python
#
# encrypt/decrypt with CCMP
from Crypto.Cipher import AES
from Crypto.Util import Counter
import binascii
import struct

# constants for 802.11
M = 8
L = 2

def bytes_to_int(s):
    """ Supports arbitrary sized positive bytestrings """
    ret = 0
    shift = 0
    for c in range(len(s)-1, -1, -1):
        ret |= ord(s[c]) << shift
        shift += 8
    return ret

def ccmp_mac(key, nonce, aad, data):
    adata = 1 if aad else 0
    flags_auth = 64 * adata + 8 * ((M-2)/2) + L-1

    # construct blocks for authentication
    b_0 = chr(flags_auth) + nonce + struct.pack(">H", len(data))
    cmac_data = b_0
    if adata:
        if len(aad) > (1<<16 - 1<<8):
            raise ValueError, "large AAD not supported"
        alen = struct.pack(">H", len(aad))
        cmac_data += alen + aad
        if len(cmac_data) % 16:
            cmac_data += "\0" * (16 - len(cmac_data) % 16)

    cmac_data += data
    if len(data) % 16:
        cmac_data += "\0" * (16 - len(data) % 16)

    aes = AES.new(key, AES.MODE_CBC, IV="\0" * 16)
    T = aes.encrypt(cmac_data)
    T = T[-16:]

    return T[0:M]

def ccmp_encrypt(key, nonce, aad, data):
    pass


def ccmp_decrypt(key, nonce, aad, data):

    flags = L-1

    # decryption
    iv = chr(flags) + nonce + "\x00\x01"
    ctr = Counter.new(128, initial_value=bytes_to_int(iv))
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)

    mac_crypt = data[-M:]
    data = data[:-M]

    pt = aes.decrypt(data)

    iv = chr(flags) + nonce + "\x00\x00"
    ctr = Counter.new(128, initial_value=bytes_to_int(iv))
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)
    mac = aes.decrypt(mac_crypt)

    print 'PT: %s' % binascii.hexlify(pt)
    print 'MAC: %s' % binascii.hexlify(mac)

    test_mac = ccmp_mac(key, nonce, aad, pt)
    print 'VERIFY: %s' % binascii.hexlify(test_mac)


def ccmp_decrypt_frame(key, frame):
    mgmt = 1
    # ath5k does this...
    # mgmt = 0
    priority = 0
    nonce_flags = mgmt << 4 | priority & 0xf
    addr2 = frame[10:16]
    ccmp_header = frame[24:24+8]
    pn0 = ccmp_header[0]
    pn1 = ccmp_header[1]
    pn2 = ccmp_header[4]
    pn3 = ccmp_header[5]
    pn4 = ccmp_header[6]
    pn5 = ccmp_header[7]

    payload = frame[32:]

    pn = pn5 + pn4 + pn3 + pn2 + pn1 + pn0
    nonce = chr(nonce_flags) + addr2 + pn
    ccmp_decrypt(key, nonce, None, payload)

def unspace(x):
    return x.replace(" ", "").replace("\n", "")

if __name__ == "__main__":

    # MFP test
    key = binascii.unhexlify('84dce95f9fee1f91baeddd2077c56846')
    frame = binascii.unhexlify('d040000000804863a2f830b5c21ab07330b5c21ab07300000100002000000000173a95ffd2d4d2bcbe85a381349f0380ad13288bad2dc5b27c50fec317e57fd0c78cd50bf8b9d579416edb1dab49dc')
    ccmp_decrypt_frame(key, frame)

    # test vectors from RFC 3610
    # key, nonce, aad, ptext, ctext
    tests = [
        (
          """C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF""",
          """00 00 00 03  02 01 00 A0  A1 A2 A3 A4  A5""",
          """00 01 02 03  04 05 06 07""",
          """08 09 0A 0B  0C 0D 0E 0F
             10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E""",
          """58 8C 97 9A  61 C6 63 D2
             F0 66 D0 C2  C0 F9 89 80  6D 5F 6B 61  DA C3 84 17
             E8 D1 2C FD  F9 26 E0"""
        ),
    ]

    for test in tests:
        (key, nonce, aad, ptext, ctext) = [binascii.unhexlify(unspace(x)) for x in test]
        ccmp_decrypt(key, nonce, aad, ctext)
