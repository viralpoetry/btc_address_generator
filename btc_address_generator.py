
import hashlib
from struct import pack
from pyelliptic import arithmetic

'''
http://offlinebitcoins.com/
'''

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def encodeBase58(num, alphabet=ALPHABET):
    """Encode a number in Base X

    `num`: The number to encode
    `alphabet`: The alphabet to use for encoding
    """
    if (num == 0):
        return alphabet[0]
    arr = []
    base = len(alphabet)
    while num:
        rem = num % base
        # print 'num is:', num
        num = num // base
        arr.append(alphabet[rem])
    arr.reverse()
    return ''.join(arr)


def decodeBase58(string, alphabet=ALPHABET):
    """Decode a Base X encoded string into the number

    Arguments:
    - `string`: The encoded string
    - `alphabet`: The alphabet to use for encoding
    """
    base = len(alphabet)
    num = 0

    try:
        for char in string:
            num *= base
            num += alphabet.index(char)
    except:
        # character not found (like a space character or a 0)
        return 0
    return num


def encodeVarint(integer):
    if integer < 0:
        print 'varint cannot be < 0'
        raise SystemExit
    if integer < 253:
        return pack('>B', integer)
    if integer >= 253 and integer < 65536:
        return pack('>B', 253) + pack('>H', integer)
    if integer >= 65536 and integer < 4294967296:
        return pack('>B', 254) + pack('>I', integer)
    if integer >= 4294967296 and integer < 18446744073709551616:
        return pack('>B', 255) + pack('>Q', integer)
    if integer >= 18446744073709551616:
        print 'varint cannot be >= 18446744073709551616'
        raise SystemExit


def encodeAddress(network_bytes, ripe):
    '''
    if version >= 2 and version < 4:
        if len(ripe) != 20:
            raise Exception("Programming error in encodeAddress: The length of a given ripe hash was not 20.")
        if ripe[:2] == '\x00\x00':
            ripe = ripe[2:]
        elif ripe[:1] == '\x00':
            ripe = ripe[1:]
    elif version == 4:
        if len(ripe) != 20:
            raise Exception("Programming error in encodeAddress: The length of a given ripe hash was not 20.")
        ripe = ripe.lstrip('\x00')
    '''

    storedBinaryData = encodeVarint(network_bytes) + ripe

    # Generate the checksum
    sha = hashlib.new('SHA256')
    sha.update(storedBinaryData)
    currentHash = sha.digest()
    sha = hashlib.new('SHA256')
    sha.update(currentHash)
    # first 4 bytes
    checksum = sha.digest()[0:4]
    # add checksum at the end of bin data
    asInt = int(storedBinaryData.encode('hex') + checksum.encode('hex'), 16)
    addr = encodeBase58(asInt)
    return '1' + addr


def get_address(seed):
    h = hashlib.new('SHA256')
    h.update(seed)
    privateEncryptionKey = h.digest().encode('hex')
    print privateEncryptionKey
    # 0 Private ECDSA Key - 256 bits
    # print 'Now let us convert them to public keys by doing an elliptic curve point multiplication.'
    # 1 Public
    publicEncryptionKey = arithmetic.privtopub(privateEncryptionKey)
    # print 'publicEncryptionKey =', publicEncryptionKey

    publicEncryptionKeyBinary = arithmetic.changebase(publicEncryptionKey, 16, 256, minlen=64)

    ripe = hashlib.new('ripemd160')
    sha = hashlib.new('SHA256')
    # 2 Sha-256 of 1
    sha.update(publicEncryptionKeyBinary)
    # print 'Sha-256: ', sha.digest().encode('hex')
    # 3 RIPEMD of 2
    ripe.update(sha.digest())
    # 4 add network bytes
    network_bytes = 00
    # print 'Ripe digest that we will encode in the address:', ripe.digest().encode('hex')
    returnedAddress = encodeAddress(network_bytes, ripe.digest())
    # print 'Encoded BTC address:', returnedAddress
    # Checksum does not validate
    return returnedAddress


if __name__ == "__main__":
    print get_address('hello world')
