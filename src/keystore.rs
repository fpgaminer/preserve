use std::io::{self, BufReader};
use crypto::pbkdf2::pbkdf2;
use crypto::chacha20::ChaCha20;
use crypto::hmac::Hmac;
use crypto::sha2::Sha512;
use crypto::mac::Mac;
use crypto::symmetriccipher::SynchronousStreamCipher;
use std::str::FromStr;
use crate::error::*;
use std::path::Path;
use std::fs;
use std::convert::TryFrom;
use data_encoding::HEXLOWER_PERMISSIVE;


// We liberally use newtypes to help prevent accidentally mixing up data, and making it more explicit what kind of data
// functions accept and return.  For example, you don't want to decrypt block data as if it were archive data.
new_type!{ secret HmacKey(128); }
new_type!{ public BlockId(32); }
new_type!{ public ArchiveId(32); }
new_type!{ public SIV(32); }

impl ToString for BlockId {
	fn to_string(&self) -> String {
		HEXLOWER_PERMISSIVE.encode(&self.0)
	}
}

impl ToString for ArchiveId {
	fn to_string(&self) -> String {
		HEXLOWER_PERMISSIVE.encode(&self.0)
	}
}

impl FromStr for ArchiveId {
	type Err = Error;

	fn from_str(s: &str) -> ::std::result::Result<ArchiveId, Self::Err> {
		let v = HEXLOWER_PERMISSIVE.decode(s.as_bytes()).map_err(|_| Error::InvalidArchiveId)?;

		ArchiveId::from_slice(&v).ok_or(Error::InvalidArchiveId)
	}
}

pub struct EncryptedArchiveName(pub Vec<u8>);
pub struct EncryptedBlock(pub Vec<u8>);
pub struct EncryptedArchiveMetadata(pub Vec<u8>);


#[derive(PartialEq, Clone)]
struct SivEncryptionKeys {
	/// Used to calculate the siv for plaintext
	siv_key: HmacKey,
	/// The cipher key
	cipher_key: HmacKey,
}

impl SivEncryptionKeys {
	fn encrypt(&self, aad: &[u8], plaintext: &[u8]) -> (SIV, Vec<u8>) {
		let siv = self.calculate_siv(aad, plaintext);
		let ciphertext = self.cipher(&siv, plaintext);

		(siv, ciphertext)
	}

	fn decrypt(&self, aad: &[u8], siv: &SIV, ciphertext: &[u8]) -> Option<Vec<u8>> {
		let plaintext = self.cipher(siv, ciphertext);
		let expected_siv = self.calculate_siv(aad, &plaintext);

		if !siv.constant_eq(&expected_siv) {
			return None;
		}

		Some(plaintext)
	}

	// TODO: This method should be private
	/// Encrypts or decrypts data using the combination of self.cipher_key and nonce.
	/// First derives an encryption key using HMAC-SHA-512 (cipher_key, nonce)
	/// and then performs ChaCha20 (derived_key, data).
	fn cipher(&self, nonce: &SIV, data: &[u8]) -> Vec<u8> {
		let big_key = {
			let mut hmac = Hmac::new(Sha512::new(), &self.cipher_key[..]);
			hmac.input(&nonce[..]);
			hmac.result()
		};
		let (chacha_key, chacha_nonce) = big_key.code().split_at(32);

		// Using slice notation here so this code panics in case we accidentally didn't derive the right size big_key
		let mut encryptor = ChaCha20::new(&chacha_key[..32], &chacha_nonce[..8]);
		let mut output = vec!(0u8; data.len());
		encryptor.process(data, &mut output);
		output
	}

	// TODO: This method should be private
	/// Calculate the unique SIV for the combination of self.siv_key, aad, and plaintext.
	/// Equivilent to: HMAC-SHA-512-256 (siv_key, aad || plaintext || le64(aad.length) || le64(plaintext.length))
	fn calculate_siv(&self, aad: &[u8], plaintext: &[u8]) -> SIV {
		let mut hmac = Hmac::new(Sha512::new(), &self.siv_key[..]);
		hmac.input(aad);
		hmac.input(plaintext);
		hmac.input(&u64::try_from(aad.len()).expect("calculate_siv: length did not fit into u64").to_le_bytes());
		hmac.input(&u64::try_from(plaintext.len()).expect("calculate_siv: length did not fit into u64").to_le_bytes());

		// Truncated to 256-bits
		SIV::from_slice(&hmac.result().code()[..32]).expect("internal error")
	}

	fn from_slice(bs: &[u8]) -> Option<SivEncryptionKeys> {
		if bs.len() != 256 {
			return None;
		}

		let (siv_key, cipher_key) = bs.split_at(128);

		Some(SivEncryptionKeys {
			siv_key: HmacKey::from_slice(siv_key)?,
			cipher_key: HmacKey::from_slice(cipher_key)?,
		})
    }
}


#[derive(PartialEq)]
pub struct KeyStore {
	/// The key all other keys are derived from.  This is the only value that needs to be saved and loaded.
	master_key: HmacKey,

	block_keys: SivEncryptionKeys,
	archive_name_keys: SivEncryptionKeys,
	blocklist_keys: SivEncryptionKeys,
	metadata_keys: SivEncryptionKeys,
}

impl KeyStore {
	/// Create a new, random, KeyStore
	pub fn new() -> KeyStore {
		let master_key = HmacKey::from_rng();

		KeyStore::from_master_key(master_key)
	}

	/// Derive the KeyStore from master_key.
	/// This is done using PBKDF2-HMAC-SHA512 (password=master_key, salt=[], iterations=1)
	/// to derive all the other keys in the KeyStore.
	pub fn from_master_key(master_key: HmacKey) -> KeyStore {
		let raw_keys = {
			let mut raw_keys = vec![0u8; 4 * 256];
			let mut hmac = Hmac::new(Sha512::new(), &master_key[..]);
			pbkdf2(&mut hmac, &[], 1, &mut raw_keys);
			raw_keys
		};

		let (block_keys, raw_keys) = raw_keys.split_at(256);
		let (archive_name_keys, raw_keys) = raw_keys.split_at(256);
		let (blocklist_keys, raw_keys) = raw_keys.split_at(256);
		let (metadata_keys, _) = raw_keys.split_at(256);

		KeyStore {
			master_key,

			block_keys: SivEncryptionKeys::from_slice(block_keys).expect("internal error"),
			archive_name_keys: SivEncryptionKeys::from_slice(archive_name_keys).expect("internal error"),
			blocklist_keys: SivEncryptionKeys::from_slice(blocklist_keys).expect("internal error"),
			metadata_keys: SivEncryptionKeys::from_slice(metadata_keys).expect("internal error"),
		}
	}

	/// Save this KeyStore to writer.  This writes a hex encoded 1024-bit master key.
	pub fn save<W: io::Write>(&self, mut writer: W) -> Result<()> {
		Ok(writer.write_all(HEXLOWER_PERMISSIVE.encode(&self.master_key[..]).as_bytes())?)
	}

	/// Load KeyStore from reader.  Expects a hex encoded 1024-bit master key, from which the KeyStore is derived.
	pub fn load<R: io::Read>(mut reader: R) -> Result<KeyStore> {
		let mut hexbytes = [0u8; 256];

		reader.read_exact(&mut hexbytes)?;

		let slice = HEXLOWER_PERMISSIVE.decode(&hexbytes).map_err(|_| Error::CorruptKeystore)?;
		let master_key = HmacKey::from_slice(&slice).ok_or(Error::CorruptKeystore)?;

		Ok(KeyStore::from_master_key(master_key))
	}

	pub fn load_from_path<P: AsRef<Path>>(path: P) -> Result<KeyStore> {
		let file = fs::File::open(path)?;
		let mut reader = BufReader::new(file);

		KeyStore::load(&mut reader)
	}

	pub fn encrypt_block(&self, block: &[u8]) -> (BlockId, EncryptedBlock) {
		let (id, ciphertext) = self.block_keys.encrypt(&[], block);

		(BlockId(id.0), EncryptedBlock(ciphertext))
	}

	pub fn decrypt_block(&self, block_id: &BlockId, encrypted_block: &EncryptedBlock) -> Result<Vec<u8>> {
		self.block_keys.decrypt(&[], &SIV(block_id.clone().0), &encrypted_block.0).ok_or(Error::CorruptBlock)
	}

	pub fn encrypt_archive_name(&self, name: &str) -> (ArchiveId, EncryptedArchiveName) {
		let (id, ciphertext) = self.archive_name_keys.encrypt(&[], name.as_bytes());

		(ArchiveId(id.0), EncryptedArchiveName(ciphertext))
	}

	pub fn decrypt_archive_name(&self, archive_id: &ArchiveId, encrypted_name: &EncryptedArchiveName) -> Result<String> {
		let plaintext = self.archive_name_keys.decrypt(&[], &SIV(archive_id.clone().0), &encrypted_name.0).ok_or(Error::CorruptArchiveName)?;

		String::from_utf8(plaintext).map_err(|_| Error::CorruptArchiveName)
	}

	pub fn encrypt_archive_metadata(&self, archive_id: &ArchiveId, metadata: &[u8]) -> EncryptedArchiveMetadata {
		let (metadata_siv, encrypted_metadata) = self.metadata_keys.encrypt(&archive_id[..], metadata);
		let mut result = Vec::new();

		result.extend_from_slice(&metadata_siv[..]);
		result.extend_from_slice(&encrypted_metadata);

		EncryptedArchiveMetadata(result)
	}

	pub fn decrypt_archive_metadata(&self, archive_id: &ArchiveId, encrypted_metadata: &EncryptedArchiveMetadata) -> Result<Vec<u8>> {
		if encrypted_metadata.0.len() < 32 {
			return Err(Error::CorruptArchiveMetadata);
		}

		let (siv, ciphertext) = encrypted_metadata.0.split_at(32);

		let plaintext = self.metadata_keys.decrypt(&archive_id[..], &SIV::from_slice(siv).expect("internal error"), ciphertext).ok_or(Error::CorruptArchiveMetadata)?;

		Ok(plaintext)
	}
}



#[cfg(test)]
mod test {
	use super::{HmacKey, SivEncryptionKeys, KeyStore, SIV};
	use crypto::pbkdf2::pbkdf2;
	use crypto::hmac::Hmac;
	use crypto::sha2::Sha512;
	use data_encoding::HEXLOWER_PERMISSIVE;
	use rand::rngs::OsRng;
	use rand::Rng;
	use rand::seq::SliceRandom;

	// TODO: As a sanity check, we should perform some statistical tests on the outputs from all the encryption functions.
	// If they are implemented correctly, all output should look indistiguishable from random.

	fn from_hexstr(hexstr: &str) -> Vec<u8> {
		HEXLOWER_PERMISSIVE.decode(hexstr.as_bytes()).unwrap()
	}

	// PBKDF2 output should be extendable (i.e. we can add keys to the KeyStore later by increasing the length passed to PBKDF2)
	#[test]
	fn test_pbkdf2_extendable() {
		let key = HmacKey::from_rng();

		let out1 = {
			let mut output = vec![0u8; 100];
			let mut hmac = Hmac::new(Sha512::new(), &key[..]);
			pbkdf2(&mut hmac, &[], 1, &mut output);
			output
		};

		let out2 = {
			let mut output = vec![0u8; 200];
			let mut hmac = Hmac::new(Sha512::new(), &key[..]);
			pbkdf2(&mut hmac, &[], 1, &mut output);
			output.truncate(100);
			output
		};

		assert_eq!(out1, out2);
	}

	// Exercises the encryption system
	#[test]
	fn test_encryption() {
		let keys = SivEncryptionKeys {
			siv_key: HmacKey::from_rng(),
			cipher_key: HmacKey::from_rng(),
		};

		let other_keys = SivEncryptionKeys {
			siv_key: HmacKey::from_rng(),
			cipher_key: HmacKey::from_rng(),
		};

		let mut plaintext = vec![0u8; OsRng.gen_range(16, 1024)];
		let mut aad = vec![0u8; OsRng.gen_range(0, 1024)];
		OsRng.fill(&mut plaintext[..]);
		OsRng.fill(&mut aad[..]);

		// The same aad and plaintext should result in the same siv and ciphertext
		let (siv1, ciphertext1) = keys.encrypt(&aad, &plaintext);
		let (siv2, ciphertext2) = keys.encrypt(&aad, &plaintext);
		assert_eq!(siv1, siv2);
		assert_eq!(ciphertext1, ciphertext2);

		// But not if the key changes (NOTE: Random chance could result in ciphertexts being equal, but the liklihood is impossibly small for our test case (which has a minimum 16 byte plaintext))
		let (other_siv, other_ciphertext) = other_keys.encrypt(&aad, &plaintext);
		assert_ne!(other_siv, siv1);
		assert_ne!(other_ciphertext, ciphertext1);

		// Changing aad or plaintext should change siv and ciphertext
		let (siv3, ciphertext3) = keys.encrypt(b"different inputs", &plaintext);
		let (siv4, ciphertext4) = keys.encrypt(&aad, b"different inputs");
		assert_ne!(siv1, siv3);
		assert_ne!(ciphertext1, ciphertext3);
		assert_ne!(siv1, siv4);
		assert_ne!(ciphertext1, ciphertext4);
		assert_ne!(siv3, siv4);
		assert_ne!(ciphertext3, ciphertext4);

		// Ciphertext should be completely different even if only one byte of plaintext is different.
		let mut mutated_plaintext = plaintext.clone();
		*mutated_plaintext.choose_mut(&mut OsRng).unwrap() ^= 0xa;
		let (siv5, ciphertext5) = keys.encrypt(&aad, &plaintext[..plaintext.len() - 1]);
		let (siv6, ciphertext6) = keys.encrypt(&aad, &mutated_plaintext);
		assert_ne!(siv1, siv5);
		assert_ne!(&ciphertext1[..plaintext.len() - 1], &ciphertext5[..]);
		assert_ne!(siv1, siv6);
		assert_ne!(&ciphertext1, &ciphertext6);

		// Length preserving
		assert_eq!(plaintext.len(), ciphertext1.len());

		// Can be decrypted
		assert_eq!(keys.decrypt(&aad, &siv1, &ciphertext1).unwrap(), plaintext);

		// Using the wrong key, siv, aad, or ciphertext should cause decryption errors
		assert!(keys.decrypt(&aad, &siv3, &ciphertext1).is_none());
		assert!(keys.decrypt(&aad, &siv1, &ciphertext3).is_none());
		assert!(keys.decrypt(b"this is not the aad you are looking for", &siv1, &ciphertext1).is_none());
		assert!(keys.decrypt(&aad, &siv1, &ciphertext1[..ciphertext1.len()-1]).is_none());
		assert!(other_keys.decrypt(&aad, &siv1, &ciphertext1).is_none());
	}

	#[test]
	fn test_known_encryption_vectors() {
		let test_keys = SivEncryptionKeys {
			siv_key: HmacKey::from_slice(&from_hexstr("2ceaccb6b306992f6affd27049b62d823a90f8125a808d292e27f5f82bf7629b8f9ada4a8135ed99cf5d5aef0ca6a69fe54104a8246e7e5a6bb210d0c945559834d3d12b40bd61cf75a462aad1a0d71d0d963957fb8270e83902f48bfd7b8e8f0603c503238c3b24c8f4ab645c521732f31bd0b3d455448f33d56102476ee5c3")).unwrap(),
			cipher_key: HmacKey::from_slice(&from_hexstr("8d45ccdc385e71c9ab0619d212fcc5118fb44c7d8b37d5dc0db4214b9787905913bdd73e3afe1db5fbea82263d3171c17d2acdf88517e6d78cdb5339f10f50ef68a55950aca578c7a170476da81a705abdf031e74bf6fbf65180e51ee14983c7d100f377cea3a27caca46fd2e2bb2cca48afd5f49cf18fbe43d580e0465b308a")).unwrap(),
		};
		let test_aad = b"aad";
		let test_plaintext = b"plaintext";
		let test_siv = SIV::from_slice(&from_hexstr("805165cad67979f70e16de978a34693972856db82c390b5bc824fc197a68d5d5")).unwrap();
		let test_ciphertext = from_hexstr("c7a4a22690419ee831");

		let (siv, ciphertext) = test_keys.encrypt(test_aad, test_plaintext);
		assert_eq!(siv, test_siv);
		assert_eq!(ciphertext, test_ciphertext);

		// This test vector was generated using an independent Python implementation
		let test_keys = SivEncryptionKeys {
			siv_key: HmacKey::from_slice(&from_hexstr("bf2bb483cb12aa8fb38370c3f1debfbe6f357ab0b4f0468107e95fa744f8f8419ad3a24dc2789e815ddd4a91852c96b79c6a79da6fd0b90a80359f1f91630a66389788d704e011870c04211527c7175f8dfa560779113ebe2f2486bde5d1cef883d9ad5b80f2e0530782c2d287107023f7b5834f98a370bb3310b39d58376d28")).unwrap(),
			cipher_key: HmacKey::from_slice(&from_hexstr("0b4d46a0f976497075238d681c7738c128eaeed7394eb700af0a00f7a452193cad43d2fa99360da728f42d1ddd45a4bc8c14ffe0eb4a40e33bf9180c5bb1201ef25615b55dd8b109f6a9f019157460aeae57bc2dd1ab6b0676386cbfd30d60ce96413dee81a339fc7d537f9a5c21bcf9836e9e40c68edaaf6a0fb18a0f7a1338")).unwrap(),
		};
		let test_aad = b"archive id";
		let test_plaintext = b"deterministic authenticated encryption";
		let test_siv = SIV::from_slice(&from_hexstr("1f5453bee0dee9b19cecc680249d3410d275801109f8780204d698fba56fb33c")).unwrap();
		let test_ciphertext = from_hexstr("5f0271a16eb3f842cd268078a34bca95b7b35a57b260edb6870a058c37461efb373a02d419e8");

		let (siv, ciphertext) = test_keys.encrypt(test_aad, test_plaintext);
		assert_eq!(siv, test_siv);
		assert_eq!(ciphertext, test_ciphertext);
	}

	#[test]
	fn test_keystore() {
		// Test vector generated manually using Python: hexlify(hashlib.pbkdf2_hmac('sha512', master_key, b'', 1, dklen=256*4))
		let master_key = HmacKey::from_slice(&from_hexstr("46efca626234765806a7079a8f51f6d172fd2912106eee2f6a826c8869286684eb27d026c5368827424be8ae915987f820af7ac9a3e670cfd16b3e8e611cb1a9cea329489f2049472b4bd924872526d012336356aa949833a279c469720e617f2e9096803a27b674e71265c417eff499b40d86da9aceb17be46d8f470d2a11db")).unwrap();
		let keystore = KeyStore::from_master_key(master_key.clone());

		let keystore_data = [
			&keystore.block_keys.siv_key[..], &keystore.block_keys.cipher_key[..],
			&keystore.archive_name_keys.siv_key[..], &keystore.archive_name_keys.cipher_key[..],
			&keystore.blocklist_keys.siv_key[..], &keystore.blocklist_keys.cipher_key[..],
			&keystore.metadata_keys.siv_key[..], &keystore.metadata_keys.cipher_key[..],
		].concat();

		assert_eq!(keystore_data, from_hexstr("054c9173d52fb8b6fd4bd001230f934ba922ee2a72931a1bf3b82e2852b5ba3ac39fdd5c49173dc345fc42d551025aa41a537dbb9ccfbcd1ac596bdb47f8e61a1e98fe4767984ddc43622e5f3c4ffd6219328bea11ec9b59b913297f8f23991fce948448202fe46923cfd5e08abe293c0f4b3080d588e84c53197b3ba8a129e77bb1a0d5edddb15563c2d41d3e90e8a5857242f17364a70e7bbf73ca717b0930288e966dc3b84dee3e4beeb89fedd92bbbc03c7a26a822eca2fe0dda425adea887bef8f968c2584e8e234583db00eed0f768db9b56bbf1def531a67e3f22f0658024a508d5bae8a04b40163ca4e5ced838987f95d9bd9f4bae2f36d77b3f4e9d254f98b6286e3a1ee1324fb996aeeec95ba4dd4aa658a93bea87ec2ba766cab922322ddb529c03db2fb6ac19d515f11331faaff3c4d26888e98bc84e165dabe842528372a60f4c3ea46bbdc47a255d21728d066d3965bb618407b57aa3f155500a0eccf2e632b0af30d54012464fcde6fe96e5e4f1931ff28bd55bf29a0c5bc21ab566b7a05d9282f9fcc91d49465404384b0512dc03ae6cd7044e366b4e4dec4e9ed869382cb3cc6db2700b9c5c0965e3847b3b045b8cfb2e0209318bd4ba29d97afbfdd738c93cf78477e0d274bae95f64187dd4f9752b959ae7dacadc7eb257661d125d1cc4a08d0243d105c7f7e2f87d63340da0ff106b759b52bc608b99a57df18e143f78d85f1e1b7340d49fee84920ee1275b85a00dce55bbed81d0db883c710ee5a9d232ae8bd1793ed33223f5b3aba8610d005b11c9d1fd6aa0148f67468d4f51c2c889fb26d66c9cbd57072bfbfa5649f759e1d13ee5397babb50674598dd51ad9e29f2684c57ec6642efb11ea67a8cc48617d696203c300bb3fae17ac4036208b7876f1e59da4126229a52103cd1995a95da4ab96d4e68ab6d62e1f15d65a71c9f54a605d03be5902ebbef49c68c190ad5948d0fbfedae17e376613ee28ada120a346c5dd70e8f762bb48cddaa006a93b041b71b1bd5e6b9c6b24558047e719a11d6293a876a149c9667642c9f311c1a4779432af7d7f39f90998dd3f3c87e73dc976cc06d825c58168711825729e91c4608b492482585085d1c9d8669fc1dd4157297d290c560ebd136aadc18c6e5f48df8b125b235586dc36fa9330fc773ae00e33fa6491cf71bc0e323c1f578e40a399b3e9a3d48b6bcb0cb098e8e8783496991d5d887be527fcdfa56fe3c27ff2c0eadaaeb5706eee881b633618dfc8468d0d9a5f131ff3a976b2cbb817978eb62caf07cf6edaa879aea79fcb9f451ab06fb2b4f40c51375d27a2dff25c3ea4afab2e2ed7b03f3c64a223e2d3deec7023ee43300b9648b12732004dc34b5b21ba087b21efcb7e0c4af8a4fb5c2a3f47a9c7e40e461d63d4d4961bc576fa35cc3a4f09a19b109bbbcaf07468"));

		// Test serialization
		let mut buffer = Vec::new();

		keystore.save(&mut buffer).unwrap();
		let restored_keystore = KeyStore::load(&buffer[..]).unwrap();

		assert!(restored_keystore == keystore);
		assert_eq!(restored_keystore.master_key, master_key);
	}

	// Tests the higher level APIs (encrypt block, encrypt archive, etc)
	// Mostly just sanity checks, since other tests verify that the underlying encryption functions are correct.
	#[test]
	fn test_encrypt_objects() {
		let keystore = KeyStore::new();
		let test_data = "just plain old data";

		let (block_id, mut block_ciphertext) = keystore.encrypt_block(test_data.as_bytes());
		let (archive_id, name_ciphertext) = keystore.encrypt_archive_name(test_data);
		let metadata_ciphertext = keystore.encrypt_archive_metadata(&archive_id, test_data.as_bytes());

		// Decryption should work
		assert_eq!(test_data.as_bytes(), &keystore.decrypt_block(&block_id, &block_ciphertext).unwrap()[..]);
		assert_eq!(test_data, keystore.decrypt_archive_name(&archive_id, &name_ciphertext).unwrap());
		assert_eq!(test_data.as_bytes(), &keystore.decrypt_archive_metadata(&archive_id, &metadata_ciphertext).unwrap()[..]);

		// Even when the data is the same, every type of object should get different IDs because different keys are used
		assert_ne!(&block_id[..], &archive_id[..]);
		assert_ne!(block_ciphertext.0, name_ciphertext.0);

		// Decryption should fail if ciphertext is modified
		block_ciphertext.0[0] ^= 0xbe;
		assert!(keystore.decrypt_block(&block_id, &block_ciphertext).is_err());

		// Make sure encrypting unicode names works
		let unicode_name = "(╯°□°）╯︵ ┻━┻";
		let (archive_id, name_ciphertext) = keystore.encrypt_archive_name(unicode_name);
		assert_eq!(unicode_name, keystore.decrypt_archive_name(&archive_id, &name_ciphertext).unwrap());
	}

	// Tests to make sure the underlying Encode function is working correctly
	#[test]
	fn test_encode() {
		let keystore = KeyStore::new();

		let test1_a = b"a";
		let test1_b = b"ab";

		let test2_a = b"aa";
		let test2_b = b"b";

		assert_ne!(keystore.block_keys.encrypt(test1_a, test1_b).0, keystore.block_keys.encrypt(test2_a, test2_b).0);
	}

	// This test makes sure that the encryption system is using the right keys for handling different types of objects.
	// For example, blocks should be encrypted using the block keys, not the archive name keys.
	#[test]
	fn test_object_encryption_keys_unique() {
		let keystore = KeyStore::new();
		let test_data = "just plain old data";

		let (block_id, block_ciphertext) = keystore.encrypt_block(test_data.as_bytes());
		let (archive_id, name_ciphertext) = keystore.encrypt_archive_name(test_data);
		let metadata_ciphertext = keystore.encrypt_archive_metadata(&archive_id, test_data.as_bytes());

		// Now try to decrypt, but corrupt all the other keys that shouldn't be used.  If the system is using the right key, that decryption should still be successful.
		let mut modified_keystore = KeyStore::new();
		modified_keystore.block_keys = keystore.block_keys.clone();
		assert_eq!(test_data.as_bytes(), &modified_keystore.decrypt_block(&block_id, &block_ciphertext).unwrap()[..]);

		let mut modified_keystore = KeyStore::new();
		modified_keystore.archive_name_keys = keystore.archive_name_keys.clone();
		assert_eq!(test_data, modified_keystore.decrypt_archive_name(&archive_id, &name_ciphertext).unwrap());

		let mut modified_keystore = KeyStore::new();
		modified_keystore.metadata_keys = keystore.metadata_keys.clone();
		assert_eq!(test_data.as_bytes(), &modified_keystore.decrypt_archive_metadata(&archive_id, &metadata_ciphertext).unwrap()[..]);
	}
}
