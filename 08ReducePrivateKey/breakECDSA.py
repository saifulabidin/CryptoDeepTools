import sys
import bitcoin
import hashlib
import txnUtils
import keyUtils

# tx = ""
tx = "" + sys.argv[1]

m = txnUtils.parseTxn(tx)
e = txnUtils.getSignableTxn(m)
z = hashlib.sha256(hashlib.sha256(bytes.fromhex(e)).digest()).digest()
z1 = z[::-1].hex()
z = z.hex()
s = keyUtils.derSigToHexSig(m[1][:-2])  # Hapus bytes.fromhex()
pub = m[2]
sigR = s[:64]
sigS = s[-64:]
sigZ = z

print("PUBKEY = " + pub)
