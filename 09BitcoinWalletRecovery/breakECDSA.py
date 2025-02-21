import sys
import bitcoin
import hashlib
import txnUtils
import keyUtils

# Get the transaction string from the command-line argument
tx = sys.argv[1]

# Parse the transaction and get the signable portion
m = txnUtils.parseTxn(tx)
e = txnUtils.getSignableTxn(m)

# Assuming 'e' is a hex-encoded string, convert it to bytes
e_bytes = bytes.fromhex(e)

# Compute double SHA-256
double_sha = hashlib.sha256(hashlib.sha256(e_bytes).digest()).digest()

# Get hex representations:
# z_hex: normal (big-endian) hex string
# z_reversed: reversed byte order as hex string
z_hex = double_sha.hex()
z_reversed = double_sha[::-1].hex()

# Convert DER signature to hex signature
s = keyUtils.derSigToHexSig(m[1][:-2])
pub = m[2]

# Extract signature R and S components (assuming they are 64 hex characters each)
sigR = s[:64]
sigS = s[-64:]
sigZ = z_hex  # You could also use z_reversed if needed

print("R = 0x" + sigR)
print("S = 0x" + sigS)
print("Z = 0x" + sigZ)
print("")
