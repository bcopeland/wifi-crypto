#!/usr/bin/python
#
# derive shared secrets with SAE

import sys
import hmac
from hashlib import sha256
import binascii
from seccure import Curve, AffinePoint, serialize_number, deserialize_number
import struct

def hmac_sha256(key, msg):
    print 'hashing: %s -> %s' %  (binascii.hexlify(key), binascii.hexlify(msg))
    h = hmac.new(key=key, msg=msg, digestmod=sha256)
    return h.digest()

def kdfz(key, label, context, length):
    iters = (length + 255) / 256
    result = ''
    for i in range(1, iters+1):
        hstr = struct.pack('<H', i) + label + context + struct.pack('<H', length)
        result += hmac_sha256(key, hstr)

    return result[0:length/8]

def bin_cmp(b1, b2):
    return cmp(b1, b2)

def addr_to_bin(addr_str):
    return ''.join([chr(int(x, 16)) for x in addr_str.split(':')])

def do_sae(curve, password, addr1, addr2, rand1, mask1, rand2, mask2):

    counter = 1
    addr1 = addr_to_bin(addr1)
    addr2 = addr_to_bin(addr2)

    p = serialize_number(curve.m)
    keylen  = len(p) * 8

    point = None
    while not point:
        print 'Counter: %d' % counter
        pwdseed = hmac_sha256(max(addr1, addr2) + min(addr1, addr2),
                              password + chr(counter))
        counter += 1

        print 'Pwd-seed: %s' % binascii.hexlify(pwdseed)
        pwdval = kdfz(pwdseed, "SAE Hunting and Pecking", p, keylen)
        print 'Pwd-value: %s' % binascii.hexlify(pwdval)

        if bin_cmp(pwdval, p) >= 0:
            continue

        try:
            point = curve.point_from_string(pwdval)
            if not point.on_curve:
                point = None
                continue
        except:
            point = None
            continue

    print 'PWE: %s, %s' % (point.x, point.y)

    # generate commit scalar and commit element from each
    # party's randomly generated values
    r_a = deserialize_number(binascii.unhexlify(rand1))
    m_a = deserialize_number(binascii.unhexlify(mask1))
    r_b = deserialize_number(binascii.unhexlify(rand2))
    m_b = deserialize_number(binascii.unhexlify(mask2))

    s_a = (r_a + m_a) % curve.order
    E_a = point * m_a
    E_a.y = curve.m-E_a.y

    s_b = (r_b + m_b) % curve.order
    E_b = point * m_b
    E_b.y = curve.m-E_b.y

    print 'a commit scalar: %s' % binascii.hexlify(serialize_number(s_a))
    print 'a commit elem x: %s' % binascii.hexlify(serialize_number(E_a.x))
    print 'a commit elem y: %s' % binascii.hexlify(serialize_number(E_a.y))
    print
    print 'b commit scalar: %s' % binascii.hexlify(serialize_number(s_b))
    print 'b commit elem x: %s' % binascii.hexlify(serialize_number(E_b.x))
    print 'b commit elem y: %s' % binascii.hexlify(serialize_number(E_b.y))

    # generate shared secret
    K_a = (point * s_b + E_b) * r_a
    K_b = (point * s_a + E_a) * r_b

    print 'a k: %s' % binascii.hexlify(serialize_number(K_a.x))
    print 'b k: %s' % binascii.hexlify(serialize_number(K_b.x))
    print

    # generate KCK and PMK
    seed = hmac_sha256('\0'*32, serialize_number(K_a.x))
    pmkid = (s_a + s_b) % curve.order
    kck_pmk = kdfz(seed, "SAE KCK and PMK", serialize_number(pmkid), 512)

    print 'KCK: %s' % binascii.hexlify(kck_pmk[0:32])
    print 'PMK: %s' % binascii.hexlify(kck_pmk[32:])
    print 'PMKID: %s' % binascii.hexlify(serialize_number(pmkid))


if __name__ == "__main__":
    if len(sys.argv) < 6:
        print "Usage: %s pw addr1 addr2 rand1 mask1 rand2 mask2" % (sys.argv[0])
        sys.exit(1)

    # NIST curve 19 (256-bit ECC)
    curve = Curve.by_name("secp256r1/nistp256")
    do_sae(curve, *sys.argv[1:])

