import ecdsa
import hashlib
import struct
import unittest
import utils
import keyUtils
import base58

# Makes a transaction from the inputs.
# outputs is a list of [redemptionSatoshis, outputScript]
def makeRawTransaction(outputTransactionHash, sourceIndex, scriptSig, outputs):
    def makeOutput(data):
        redemptionSatoshis, outputScript = data
        # Pack satoshis as 8-byte little-endian and convert to hex.
        redemptionHex = struct.pack("<Q", redemptionSatoshis).hex()
        # Convert outputScript (a hex string) to bytes to get its length.
        outputScriptBytes = bytes.fromhex(outputScript)
        lengthHex = '%02x' % len(outputScriptBytes)
        return redemptionHex + lengthHex + outputScript
    formattedOutputs = ''.join(map(makeOutput, outputs))
    
    # Reverse the output transaction hash (hex string) by converting to bytes,
    # reversing, then converting back to hex.
    txHashReversed = bytes.fromhex(outputTransactionHash)[::-1].hex()
    indexHex = struct.pack('<L', sourceIndex).hex()
    scriptSigBytes = bytes.fromhex(scriptSig)
    scriptSigLenHex = '%02x' % len(scriptSigBytes)
    
    return ("01000000" +                     # 4-byte version
            "01" +                           # number of inputs (varint)
            txHashReversed +
            indexHex +
            scriptSigLenHex + scriptSig +
            "ffffffff" +                     # sequence
            "%02x" % len(outputs) +          # number of outputs (varint)
            formattedOutputs +
            "00000000")                     # lockTime

# Returns [first, sig, pub, rest]
def parseTxn(txn):
    first = txn[0:41*2]
    scriptLen = int(txn[41*2:42*2], 16)
    script = txn[42*2:42*2+2*scriptLen]
    sigLen = int(script[0:2], 16)
    sig = script[2:2+sigLen*2]
    pubLen = int(script[2+sigLen*2:2+sigLen*2+2], 16)
    pub = script[2+sigLen*2+2:]
    assert len(pub) == pubLen*2
    rest = txn[42*2+2*scriptLen:]
    return [first, sig, pub, rest]

# Substitutes the scriptPubKey into the transaction and appends the hash code type.
def getSignableTxn(parsed):
    first, sig, pub, rest = parsed
    # keyUtils.pubKeyToAddr returns an address string.
    # base58.b58decode_check returns bytes.
    inputAddr = base58.b58decode_check(keyUtils.pubKeyToAddr(pub))
    return first + "1976a914" + inputAddr.hex() + "88ac" + rest + "01000000"

# Verifies that a transaction is properly signed.
def verifyTxnSignature(txn):
    parsed = parseTxn(txn)
    signableTxn = getSignableTxn(parsed)
    # Compute double SHA-256 of signableTxn (convert from hex to bytes first)
    hashToSign = hashlib.sha256(hashlib.sha256(bytes.fromhex(signableTxn)).digest()).digest().hex()
    # Check that the hashtype byte is correct.
    assert parsed[1][-2:] == '01'
    sig = keyUtils.derSigToHexSig(parsed[1][:-2])
    public_key = parsed[2]
    # Assuming public_key is a hex string starting with '04'; skip the prefix.
    vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key[2:]), curve=ecdsa.SECP256k1)
    if not vk.verify_digest(bytes.fromhex(sig), bytes.fromhex(hashToSign)):
        raise AssertionError("Signature verification failed")

def makeSignedTransaction(privateKey, outputTransactionHash, sourceIndex, scriptPubKey, outputs):
    myTxn_forSig = makeRawTransaction(outputTransactionHash, sourceIndex, scriptPubKey, outputs) + "01000000"
    s256 = hashlib.sha256(hashlib.sha256(bytes.fromhex(myTxn_forSig)).digest()).digest()
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(privateKey), curve=ecdsa.SECP256k1)
    # Append the hash code type as a single byte.
    sig_der = sk.sign_digest(s256, sigencode=ecdsa.util.sigencode_der) + b'\x01'
    sig_hex = sig_der.hex()
    pubKey = keyUtils.privateKeyToPublicKey(privateKey)
    # Assume utils.varstr expects bytes; convert sig_hex and pubKey from hex.
    scriptSig = utils.varstr(bytes.fromhex(sig_hex)).hex() + utils.varstr(bytes.fromhex(pubKey)).hex()
    signed_txn = makeRawTransaction(outputTransactionHash, sourceIndex, scriptSig, outputs)
    verifyTxnSignature(signed_txn)
    return signed_txn

class TestTxnUtils(unittest.TestCase):

    def test_verifyParseTxn(self):
        txn = (
            "0100000001a97830933769fe33c6155286ffae34db44c6b8783a2d8ca52ebee6414d399ec300000000" +
            "8a47" +
            "304402202c2e1a746c556546f2c959e92f2d0bd2678274823cc55e11628284e4a13016f80220797e716835f9dbcddb752cd0115a970a022ea6f2d8edafff6e087f928e41baac01" +
            "41" +
            "04392b964e911955ed50e4e368a9476bc3f9dcc134280e15636430eb91145dab739f0d68b82cf33003379d885a0b212ac95e9cddfd2d391807934d25995468bc55" +
            "ffffffff02015f0000000000001976a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac204e000000000000" +
            "1976a914348514b329fda7bd33c7b2336cf7cd1fc9544c0588ac00000000"
        )
        parsed = parseTxn(txn)
        self.assertEqual(parsed[0], "0100000001a97830933769fe33c6155286ffae34db44c6b8783a2d8ca52ebee6414d399ec300000000")
        self.assertEqual(parsed[1], "304402202c2e1a746c556546f2c959e92f2d0bd2678274823cc55e11628284e4a13016f80220797e716835f9dbcddb752cd0115a970a022ea6f2d8edafff6e087f928e41baac01")
        self.assertEqual(parsed[2], "04392b964e911955ed50e4e368a9476bc3f9dcc134280e15636430eb91145dab739f0d68b82cf33003379d885a0b212ac95e9cddfd2d391807934d25995468bc55")
        self.assertEqual(parsed[3],
            "ffffffff02015f0000000000001976a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac204e000000000000" +
            "1976a914348514b329fda7bd33c7b2336cf7cd1fc9544c0588ac00000000"
        )

    def test_verifySignableTxn(self):
        txn = (
            "0100000001a97830933769fe33c6155286ffae34db44c6b8783a2d8ca52ebee6414d399ec300000000" +
            "8a47" +
            "304402202c2e1a746c556546f2c959e92f2d0bd2678274823cc55e11628284e4a13016f80220797e716835f9dbcddb752cd0115a970a022ea6f2d8edafff6e087f928e41baac01" +
            "41" +
            "04392b964e911955ed50e4e368a9476bc3f9dcc134280e15636430eb91145dab739f0d68b82cf33003379d885a0b212ac95e9cddfd2d391807934d25995468bc55" +
            "ffffffff02015f0000000000001976a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac204e000000000000" +
            "1976a914348514b329fda7bd33c7b2336cf7cd1fc9544c0588ac00000000"
        )
        parsed = parseTxn(txn)
        myTxn_forSig = (
            "0100000001a97830933769fe33c6155286ffae34db44c6b8783a2d8ca52ebee6414d399ec300000000" +
            "1976a914" + "167c74f7491fe552ce9e1912810a984355b8ee07" + "88ac" +
            "ffffffff02015f0000000000001976a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac204e000000000000" +
            "1976a914348514b329fda7bd33c7b2336cf7cd1fc9544c0588ac00000000" +
            "01000000"
        )
        signableTxn = getSignableTxn(parsed)
        self.assertEqual(signableTxn, myTxn_forSig)

    def test_verifyTxn(self):
        txn = (
            "0100000001a97830933769fe33c6155286ffae34db44c6b8783a2d8ca52ebee6414d399ec300000000" +
            "8a47" +
            "304402202c2e1a746c556546f2c959e92f2d0bd2678274823cc55e11628284e4a13016f80220797e716835f9dbcddb752cd0115a970a022ea6f2d8edafff6e087f928e41baac01" +
            "41" +
            "04392b964e911955ed50e4e368a9476bc3f9dcc134280e15636430eb91145dab739f0d68b82cf33003379d885a0b212ac95e9cddfd2d391807934d25995468bc55" +
            "ffffffff02015f0000000000001976a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac204e000000000000" +
            "1976a914348514b329fda7bd33c7b2336cf7cd1fc9544c0588ac00000000"
        )
        verifyTxnSignature(txn)

    def test_makeRawTransaction(self):
        # Example from http://bitcoin.stackexchange.com/questions/3374/how-to-redeem-a-basic-tx
        txn = makeRawTransaction(
            "f2b3eb2deb76566e7324307cd47c35eeb88413f971d88519859b1834307ecfec",  # output transaction hash
            1,  # sourceIndex
            "76a914010966776006953d5567439e5e39f86a0d273bee88ac",              # scriptSig
            [[99900000, "76a914097072524438d003d23a2f23edb65aae1bb3e46988ac"]],   # outputScript
        ) + "01000000"  # hash code type
        self.assertEqual(txn,
            "0100000001eccf7e3034189b851985d871f91384b8ee357cd47c3024736e5676eb2debb3f2" +
            "010000001976a914010966776006953d5567439e5e39f86a0d273bee88acffffffff" +
            "01605af405000000001976a914097072524438d003d23a2f23edb65aae1bb3e46988ac" +
            "0000000001000000"
        )

    def test_makeSignedTransaction(self):
        # Transaction from
        # https://blockchain.info/tx/901a53e7a3ca96ed0b733c0233aad15f11b0c9e436294aa30c367bf06c3b7be8
        # From 133t to 1KKKK
        privateKey = keyUtils.wifToPrivateKey("5Kb6aGpijtrb8X28GzmWtbcGZCG8jHQWFJcWugqo3MwKRvC8zyu")  # 133t
        signed_txn = makeSignedTransaction(
            privateKey,
            "c39e394d41e6be2ea58c2d3a78b8c644db34aeff865215c633fe6937933078a9",  # previous tx hash
            0,  # sourceIndex
            keyUtils.addrHashToScriptPubKey("133txdxQmwECTmXqAr9RWNHnzQ175jGb7e"),
            [[24321, keyUtils.addrHashToScriptPubKey("1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa")],
             [20000, keyUtils.addrHashToScriptPubKey("15nhZbXnLMknZACbb3Jrf1wPCD9DWAcqd7")]]
        )
        # Verify the signature; an exception will be raised on failure.
        verifyTxnSignature(signed_txn)

if __name__ == '__main__':
    unittest.main()
