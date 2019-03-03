# Preserve Cryptography

This document describes the cryptography used by Preserve.

## Overview

The goals of Preserve's cryptography:

 * Protect the privacy and safety of users.
 * Be simple.
 * Require as little trust as possible.

Speed comes secondary to these primary goals; we often opt for security at the cost of speed.  Simple constructions are easier to implement with less bugs, and easier to audit.  Simple implementations are often chosen at the cost of speed.

The current system provides the following (as long as your keys are safe):

 * The contents of your backups cannot be read by attackers, even if your backups are stolen/leaked.
 * The contents of your backups cannot be read by backends.  i.e. you do not need to trust your privacy to a cloud-based backend.
 * A malicious backend can corrupt your backups, but because backups are authenticated you'll know if that happens and Preserve won't restore malicious data (i.e. attackers cannot inject viruses into your backups).
 * Deduplication.

Preserve does, however, have these caveats:

 * It does not hide the length of your data.  i.e. the size of your backups, and in some cases the sizes of your files.
 * Backends can see which blocks of encrypted data belong to which backups.  A backend can always deduce this information based on your usage patterns, so Preserve makes no effort to hide this information.

These caveats are not unique to Preserve, and are not generally considered dangerous, but are noted for transparency.

Preserve is not weak to the usual failings of secure deduplication (e.g. confirmation attacks), because the keys used are unique to the user.  This is not only a security measure, but also a privacy measure.  For example, some cloud services using global convergent encryption schemes can tell what users are storing based on the unique hashes.  This is not possible with Preserve; a backend cannot deduce what a user is storing from block hashes.

Preserve uses the SIV construction to efficiently achieve its goal of secure deduplication.  The SIV construction makes encryption of blocks deterministic and provides each with a unique ID that can be used to reference the encrypted data.  SIV and its security proof are provided in the citation (Deterministic authenticated-encryption).  Preserve is thus DAE secure.  The SIV construction requires a PRF-secure primitive, and an IND$-secure IV cipher.  In Preserve we use HMAC-SHA-512-256 as the PRF-secure primitive, and ChaCha20 wrapped by HMAC-SHA-512 as the IND$-secure cipher.

HMAC-SHA-512-256 (which is HMAC-SHA-512 truncated to 256-bits, not HMAC-SHA-512/256) is used because: it's faster on 64-bit platforms than HMAC-SHA-256; it is well seasoned, unlike potentially better functions like Blake, while still being fast enough; it's a random oracle according to the citation (Merkle-Damgård revisited); the HMAC construction has been shown to provide additional security when the underlying function fails, so it's a potentially more secure choice compared to SHA-512-256 even though SHA-512-256 has all the same properties.

ChaCha20 is wrapped by HMAC-SHA-512 using `HMAC-SHA-512(key, IV)` to derive a 256-bit key and 64-bit nonce for the invocation of ChaCha20.  Basically it turns ChaCha20 into a cipher with a 256-bit nonce.  This is used because the usual ChaCha20 cipher only accepts a 64-bit nonce, while our SIV implementation calls for 256-bits.  Reasons why we didn't use something else: XChaCha20 is a commonly used extension of ChaCha20 and derives its security straightforwardly from the XSalsa20 paper, however it only has a 192-bit nonce.  192-bits *might* be enough.  I would need to review the security proof for the SIV construction in-depth to know for sure how the security margin is affected by reducing the nonce space.  An XXChaCha20 primitive could be invented (three-layer cascade), but this requires studying the XSalsa20 security proof in depth to see if it covers the three-layer case.  Both options are likely secure, but require additional scrutiny (by myself and anyone reviewing Preserve's security).  In contrast we know for sure that HMAC-SHA-512 wrapped ChaCha20 fulfills the requirements and we already have HMAC-SHA-512.

SIV also calls for an Encode function, used to encode the input to the PRF.  It must be such that Encode uniquely encodes its inputs (given any input A, there exists no input B where `A!=B` and `Encode(A) = Encode(B)`).  Preserve simply uses `Encode(AAD, Plaintext) = AAD || Plaintext || le64encode(AAD.length) || le64encode(Plaintext.length)`.


### Citations

(Merkle-Damgård revisited) Coron, Jean-Sébastien, et al. "Merkle-Damgård revisited: How to construct a hash function." Annual International Cryptology Conference. Springer, Berlin, Heidelberg, 2005.

(Deterministic authenticated-encryption) Abbadi, Mohammad, et al. "Deterministic authenticated-encryption: A provable-security treatment of the keywrap problem." Journal of Applied Sciences 8.21 (1996): pp-1.



## Primitives

* HMAC-SHA-512
* HMAC-SHA-512-256
* ChaCha20
* scrypt
* PBKDF2-SHA-256
* PBKDF2-SHA-512
* SHA-512
* SHA-256



## Keys

1024-bit keys are used because keying material here is "free" and they are the exact size that HMAC-SHA-512 ends up using.

```
SivEncryptionKeys:
	* siv_key: 1024-bits
	* kdf_key: 1024-bits
```



## Functions

### SivEncrypt
`aad` is Additional Authenticated Data.  AAD is not included in the resulting ciphertext, but it is used as part of the authentication and thus SIV generation.  The same plaintext will encrypt differently if the AAD is different.  AAD is useful, for example, for associating an Archive's Metadata with an ArchiveId.  In this manner an archive's components cannot be mixed up, otherwise we would detect an authentication failure.

The returned SIV can be treated as a unique, deterministic identifier (ID) for the (aad, plaintext) pair.  The ID does not need to be secret.

```
SivEncrypt (keys: SivEncyptionKeys, aad: [u8], plaintext: [u8]) -> ([u8; 32], [u8])
	mac_data = Encode (a=aad, b=plaintext)
	siv = HMAC-SHA-512-256 (key=keys.siv_key, data=mac_data)
	ciphertext = Cipher (key=keys.kdf_key, nonce=siv, data=plaintext)

	return siv, ciphertext
```

### SivDecrypt
```
SivDecrypt (keys: SivEncryptionKeys, siv: [u8; 32], aad: [u8], ciphertext: [u8]) -> [u8]
	plaintext = Cipher (key=keys.kdf_key, nonce=siv, data=ciphertext)
	mac_data = Encode (a=aad, b=plaintext)
	expected_siv = HMAC-SHA-512-256 (key=keys.siv_key, data=mac_data)
	assert!(constant_time_eq (siv, expected_siv))

	return plaintext
```

### PassphraseEncrypt
```
PassphraseEncrypt (passphrase: String, plaintext: [u8]) -> [u8]
	salt = csrandom(32)
	params = time_scrypt (1 hour)
	keys = scrypt (params, salt, passphrase)
	siv, ciphertext = SivEncrypt (keys, salt || params, plaintext)

	return salt || params || siv || ciphertext
```

### PassphraseDecrypt
It's important to sanity check the params.  An attacker could, for example, give us parameters which tell us to run scrypt for several years, use all our RAM, etc.  Though this is not dangerous, it is a DoS vector.

```
PassphraseDecrypt (passphrase: String, sealed_data: [u8]) -> [u8]
	salt, params, siv, ciphertext = sealed_data
	sanity_check_params (params)
	keys = scrypt (params, salt, passphrase)
	plaintext = SivDecrypt (keys, siv, salt || params, ciphertext)

	return plaintext
```

### Cipher
`Cipher` is symmetrical; it is both the encryption and decryption function.  It behaves as an IND$-secure cipher with a 1024-bit key and 256-bit nonce.

```
Cipher (key: [u8; 128], nonce: [u8; 32], data: [u8])
	chacha_key, chacha_nonce = HMAC-SHA-512 (key, nonce).split (32)

	return ChaCha20 (chacha_key, chacha_nonce[:8], data)
```

### Encode
Uniquely encodes the AAD and plaintext for MAC calculation.

For all `A`, `B`, `C`, and `D` where `(A, B) != (C, D)` it is true that `Encode(A, B) != Encode(C, D)`.

```
Encode (a: [u8], b: [u8])
	return a || b || le64encode (a.length) || le64encode (b.length)
```



## Block

### Encryption

Given the plaintext for a block, encryption is as follows:

```
BlockId, EncryptedBlock = SivEncrypt (Keystore.block, [], Block)
```

Store `BlockId = EncryptedBlock` in the backend.  Store `BlockId` in the archive.


### Decryption

The decryption is as follows (after retreiving BlockId and EncryptedBlock from the backend):

```
Block = SivDecrypt (Keystore.block, BlockId, [], EncryptedBlock)
```


### Notes

Our encryption scheme ensures that given the same Block and Keystore, BlockId and EncryptedBlock will always be the same, allowing deduplication.



## Archive

### Encryption

```
ArchiveId, EncryptedName = SivEncrypt (Keystore.archive_name, [], Name)
BlocklistId, _ = SivEncrypt (Keystore.archive_blocklist, ArchiveId || Blocklist, [])
MetadataId, EncryptedMetadata = SivEncrypt (Keystore.archive_metadata, ArchiveId, Metadata)
```

Use `ArchiveId` to refer to the archive on the backend.  Store `ArchiveId = EncryptedName, BlocklistId, Blocklist, MetadataId, EncryptedMetadata` on the backend.


### Decryption

```
Name = SivDecrypt (Keystore.archive_name, ArchiveId, [], None)
_ = SivDecrypt (Keystore.archive_blocklist, BlocklistId, ArchiveId || Blocklist, [])
Metadata = SivDecrypt (Keystore.archive_metadata, MetadataId, ArchiveId, EncryptedMetadata)
```


### Notes

Blocklist is left plaintext so the backend can read it and use it for refcounting.  The BlockIds themselves are opaque and so don't reveal any sensitive information, other than which blocks are associated with which archives (which the backend could infer from usage patterns regardless).

Archives are stored in pieces so the backend can return any piece when asked.  For example, when asked to list all the archives the backend can just return a list of EncryptedNames.

It is important to run `SivDecrypt` on the BlocklistId to authenticate the Blocklist.



## Keystore

A Keystore contains all the keys needed to encrypt and decrypt backups.  A Keystore is derived from a 1024-bit MasterKey.  We use this derivation scheme so that we can easily add other derived keys to the Keystore in later versions if necessary.

The Keystore is derived from the MasterKey using `PBKDF2-HMAC-512 (password=MasterKey, salt='', iterations=1, length=*)`, where length depends on the amount of keying material that Keystore needs.  It is important to note that `PBKDF2(length=100)` is equal to `PBKDF2(length=200)[..100]` as long as the other parameters are the same.  This is what allows us to add new keys to the Keystore later.

The MasterKey can be encrypted using a passphrase and stored on one or several backends.  Encryption uses scrypt KDF with parameters that require an hour on the average computer.  This hellishly difficult KDF is used because the passphrase is rarely needed (only during recovery on a new computer) and it provides exceptional security in the case where the encrypted MasterKey is leaked.  This makes it safer for MasterKeys to be stored on backends, which allows a more convenient system.

Preserve is expected to keep a decrypted copy of the Keystore locally, so backups can be made without the user's password.

The Keystore has separate sets of encryption keys for every type of object that gets encrypted (Blocks, Archive names, etc).  Keying material is "free", so we might as well.  It also means that the set of IDs for each type of object is different, so we don't accidentally mix up data.


### Encryption

```
EncryptedMasterKey = PassphraseEncrypt (Passphrase, MasterKey)
```

Store `EncryptedMasterKey`


### Decryption

```
MasterKey = PassphraseDecrypt (Passphrase, EncryptedMasterKey)
```

