from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


class InvalidKeySize(Exception):

    def __init__(self, *args):
        super().__init__(args)


def generate_block_size(public, passphrase=None):
    """
    Gets the size of each decryption block and maximum size for encryption blocks
    :param public: Public key to use for the checks
    :param passphrase: Passphrase for the key
    :return: (Size of decryption blocks, Maximum size for encryption blocks)
    """
    key = RSA.import_key(public, passphrase)
    return int((key.size_in_bits() - 384)/8 + 6)


def generate(bits, passphrase_public=None, passphrase_private=None):
    """
    Generate a pair of RSA keys
    :param bits: Bits of the key
    :param passphrase_public: Passphrase for the public key
    :param passphrase_private: Passphrase for the private key
    :return: {"PUBLIC":public key, "PRIVATE":private key}
    """
    if bits % 8 != 0 or bits < 1024:
        raise InvalidKeySize("The key must be a multiple of 8 and >= 1024")
    returneo = {"PUBLIC": None, "PRIVATE": None}
    key = RSA.generate(bits)
    returneo["PUBLIC"] = key.publickey().exportKey(passphrase=passphrase_public)
    returneo["PRIVATE"] = key.exportKey(passphrase=passphrase_private)
    return returneo


def encrypt_block(msg, key):
    """
    Encrypt plain-text block
    :param msg: Block to encrypt
    :param key: Public key(object not string) to use
    :return: Bits object representing the message encrypted
    """
    cipher_rsa = PKCS1_OAEP.new(key)
    msg = cipher_rsa.encrypt(msg)
    return msg


def encrypt(msg, public, max_block=None, passphrase=None):
    """
    Encrypts a given message
    :param msg: Message to encrypt(bytes or string)
    :param public: Public key to use
    :param max_block: Block size(use generate_block_size for a list of permitted block sizes)
    :param passphrase: Passphrase for the key
    :return: Bytes object representing the encrypted message
    """
    if max_block is None:
        max_block = generate_block_size(public, passphrase)
    if type(msg) == str:
        msg = msg.encode()
    key = RSA.import_key(public, passphrase)
    returneo = b""
    for x in range(0, len(msg), max_block):
        block = msg[x:x + max_block]
        returneo += encrypt_block(block, key)
    return returneo


def decrypt_block(msg, key):
    """
    Decrypt message
    :param msg: Bits object to decrypt
    :param key: Private key to use
    :return: Message's bytes
    """
    cipher_rsa = PKCS1_OAEP.new(key)
    msg = cipher_rsa.decrypt(msg)
    return msg


def decrypt(msg, private, passphrase=None):
    """
    Decrypt the given message
    :param msg: Bytes object to decrypt
    :param private: Private key to use
    :param passphrase: Passphrase for the key
    :return: Bytes object decrypted
    """
    key = RSA.import_key(private, passphrase)
    returneo = b""
    max_block = key.size_in_bytes()
    for x in range(0, len(msg), max_block):
        block = msg[x:x+max_block]
        returneo += decrypt_block(block, key)
    return returneo
