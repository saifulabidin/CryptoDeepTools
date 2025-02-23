import ecdsa
import hashlib
import struct
import unittest
import keyUtils
import base58

def makeRawTransaction(outputTransactionHash, sourceIndex, scriptSig, outputs):
    def makeOutput(data):
        redemptionSatoshis, outputScript = data
        return struct.pack("<Q", redemptionSatoshis).hex() + '%02x' % len(bytes.fromhex(outputScript)) + outputScript
    
    formattedOutputs = ''.join(map(makeOutput, outputs))

    return ("01000000" +
        "01" +
        bytes.fromhex(outputTransactionHash)[::-1].hex() +
        struct.pack('<L', sourceIndex).hex() +
        '%02x' % len(bytes.fromhex(scriptSig)) + scriptSig +
        "ffffffff" +
        "%02x" % len(outputs) +
        formattedOutputs +
        "00000000"
    )

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

def getSignableTxn(parsed):
    first, sig, pub, rest = parsed
    inputAddr = base58.b58decode_check(keyUtils.pubKeyToAddr(pub)).hex()
    return first + "1976a914" + inputAddr + "88ac" + rest + "01000000"

def verifyTxnSignature(txn):
    parsed = parseTxn(txn)
    signableTxn = getSignableTxn(parsed)
    hashToSign = hashlib.sha256(hashlib.sha256(bytes.fromhex(signableTxn)).digest()).digest().hex()
    
    assert parsed[1][-2:] == '01'  # hashtype

    sig = keyUtils.derSigToHexSig(parsed[1][:-2])
    public_key = parsed[2]
    vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key[2:]), curve=ecdsa.SECP256k1)

    assert vk.verify_digest(bytes.fromhex(sig), bytes.fromhex(hashToSign))

if __name__ == '__main__':
    unittest.main()
