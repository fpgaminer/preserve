HMAC-SHA-256
ChaCha20
Curve25519


HMAC key length = 512-bits
KDF key length = 1024-bits


KDF (key, secret):
	encryption_key = HMAC(key[0:512], secret)
	nonce = HMAC(key[512:1024], secret)[0:64]

	return encryption_key, nonce


ENC (key, plaintext):
	Run ChaCha20 with a key of key.encryption_key and a 64-bit nonce of key.nonce




#Block#
Notes:
Deterministic encryption; the same block will encrypt to the same ciphertext with the same id, etc.


Storage Format:
	Key:
	 32 block id

	Value:
       	  * ciphertext
 	 32 mac

Keys:
	K0, K1 = HMAC keys
	K2 = KDF key
	K3 = HMAC key

Encrypt:
	# Inputs
	B = input plaintext

	# Algrorithm
	secret = HMAC(K0, B)
	id = HMAC(K1, secret)
	key = KDF(K2, secret)
	ciphertext = ENC(key, B)

	mac = HMAC(K3, id + ciphertext)

	# Outputs
	id       # Use to refer to this block in a Key-Value store (this is the Key)
	ciphertext + mac  # The encrypted payload (in a Key-Value store, this is Value)
	secret   # Store this in the archive.  The block id and encryption keys can be regenerated from it.

Fetch:
	Fetching a block can be achived by calculating the block's id from the block's secret (which is stored in the archive).
	id = HMAC(K1, secret)
	The fetch the block

Decrypt:
	# Inputs
	ciphertext = input ciphertext
	mac = input mac
	secret = input secret

	# Algorithm
	id = KDF(K1, secret)

	assert(HMAC(K3, id + ciphertext) == mac)

	key = KDF(K2, secret)
	plaintext = ENC(key, ciphertext)

	# Outputs
	plaintext



#Archive Name#
Notes:
Deterministic encryption; the same archive name will encrypt to the same encrypted name.
Archive names are UTF-8.
Archive names cannot exceed 127 bytes.
Encrypted archive names will not exceed 255 bytes.


Storage Format:
	base64:
	 32 id
	  * ciphertext
	 32 mac

Keys:
	K0 = HMAC key
	K1 = KDF key
	K2 = HMAC key

Encrypt:
	# Inputs
	N = archive name

	# Algorithm
	id = HMAC(K0, N)
	key = KDF(K1, id)
	ciphertext = ENC(key, N)

	mac = HMAC(K2, id + ciphertext)

	# Outputs
	base64(id + ciphertext + mac)  # Encrypted payload

Decrypt:
	# Inputs
	id = input id
	ciphertext = input ciphertext
	mac = input mac

	# Algorithm
	assert(HMAC(K2, id + ciphertext) == mac)

	key = KDF(K1, id)
	plaintext = ENC(key, ciphertext)

	# Outputs
	plaintext



#Archive#
Notes:
Uses public key encryption.
HMAC is calculated with encrypted archive name included so that malicious parties can't mix up archive names and archive contents.  We use the encrypted archive name to allow verifying backup integrity without decrypting anything.

Storage Format:
	Key:
	 * encrypted archive name

	Value:
	 * ciphertext
	32 mac

Keys:
	K0 = KDF key
	K1 = HMAC key
	p, P = Curve25519 keypair

Encrypt:
	# Inputs
	X = encrypted archive name (before base64)
	A = plaintext archive

	# Algorithm
	e = random(32)
	E = curve25519_base(e)
	shared = curve25519(e, P)
	key = KDF(K0, shared)

	ciphertext = ENC(key, A)

	mac = HMAC(K1, X + E + ciphertext)

	# Outputs
	E + ciphertext + mac  # Encrypted payload
