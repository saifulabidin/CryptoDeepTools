import ecdsa
import ecdsa.der
import ecdsa.util
import hashlib
import unittest
import base58

def privateKeyToWif(key_hex):
    return base58.b58encode_check(b'\x80' + bytes.fromhex(key_hex)).decode()

def wifToPrivateKey(s):
    return base58.b58decode_check(s).hex()

def derSigToHexSig(s):
    s, junk = ecdsa.der.remove_sequence(bytes.fromhex(s) if isinstance(s, str) else s)
    assert junk == b''
    x, s = ecdsa.der.remove_integer(s)
    y, s = ecdsa.der.remove_integer(s)
    return f'{x:064x}{y:064x}'


def privateKeyToPublicKey(s):
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(s), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return ('04' + vk.to_string().hex())

def keyToAddr(s):
    return pubKeyToAddr(privateKeyToPublicKey(s))

def pubKeyToAddr(s):
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(bytes.fromhex(s)).digest())
    return base58.b58encode_check(ripemd160.digest()).decode()

class TestKey(unittest.TestCase):
    def test_privateKeyToWif(self):
        w = privateKeyToWif("0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D")
        self.assertEqual(w, "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")

    def test_WifToPrivateKey(self):
        k = wifToPrivateKey("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")
        self.assertEqual(k.upper(), "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D")

if __name__ == '__main__':
    unittest.main()
