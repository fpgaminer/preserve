use std::env::home_dir;
use std::io::{self, BufReader, Read};
use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crypto;
use crypto::chacha20::ChaCha20;
use crypto::hmac::Hmac;
use crypto::sha2::Sha256;
use crypto::mac::{Mac, MacResult};
use crypto::symmetriccipher::SynchronousStreamCipher;
use crypto::curve25519;

use error::*;
use cmds::keygen::VaultConfig;

use rand::{OsRng, Rng};
use rustc_serialize;
use rustc_serialize::json;
use rustc_serialize::hex::{ToHex, FromHex};
use rustc_serialize::base64::{self, ToBase64, FromBase64, FromBase64Error};
use vault::Client;


new_type!{
	secret HmacKey(64);
}

new_type!{
	secret Curve25519PrivateKey(32);
}

new_type!{
	public Curve25519PublicKey(32);
}

new_type!{
	secret ChaCha20Key(32);
}

new_type!{
	secret ChaCha20Nonce(8);
}

#[derive(RustcDecodable, RustcEncodable)]
struct EncryptionKey {
    pub key: ChaCha20Key,
    pub nonce: ChaCha20Nonce,
}

#[derive(RustcDecodable, RustcEncodable, PartialEq, Debug)]
pub struct KdfKey {
    pub key_key: HmacKey,
    pub nonce_key: HmacKey,
}

new_type!{
	secret Secret(32);
}

new_type!{
	public BlockId(32);
}

pub struct EncryptedArchiveName(pub Vec<u8>);
#[derive(PartialEq, Debug)]
pub struct EncryptedBlock(pub Vec<u8>);
pub struct EncryptedArchive(pub Vec<u8>);


// We use lots of keying data because it's cheap to do so, adds lots of entropy to the system,
// and provides extra layers of protection in case a key is accidentally leaked or improperly
// used.
#[derive(RustcDecodable, RustcEncodable, PartialEq, Debug)]
pub struct KeyStore {
    /// Used to calculate the block secret from a block's plaintext.
    pub block_secret_key: HmacKey,
    /// Used to calculate the block's id from the secret
    pub block_id_key: HmacKey,
    /// Used to calculate the encryption key from secret
    pub block_kdf_key: KdfKey,
    /// Used to calculate the HMAC of an encrypted block
    pub block_hmac_key: HmacKey,

    // TODO: This should be kept encrypted
    /// Curve25519 private key; used to decrypt archives
    pub archive_private_key: Curve25519PrivateKey,
    /// Curve25519 public key; used to encrypt archives
    pub archive_public_key: Curve25519PublicKey,
    /// Used to calculate encryption key from Curve25519 shared secret
    pub archive_kdf_key: KdfKey,
    /// Used to calculate MAC of encrypted archives
    pub archive_hmac_key: HmacKey,

    /// Used to calculate archive id
    pub archive_name_id_key: HmacKey,
    /// Used to calculate the archive name encryption key from the archive id
    pub archive_name_kdf_key: KdfKey,
    /// Used to calculate the HMAC of the encrypted archive name
    pub archive_name_hmac_key: HmacKey,
}


impl KeyStore {
    pub fn new() -> KeyStore {
        let mut rng = OsRng::new().expect("OsRng failed to initialize");
        let archive_private_key: Curve25519PrivateKey = rng.gen();
        let archive_public_key = crypto::curve25519::curve25519_base(&archive_private_key[..]);

        KeyStore {
            block_secret_key: rng.gen(),
            block_id_key: rng.gen(),
            block_kdf_key: KdfKey {
                key_key: rng.gen(),
                nonce_key: rng.gen(),
            },
            block_hmac_key: rng.gen(),

            archive_private_key: archive_private_key,
            archive_public_key: Curve25519PublicKey::from_slice(&archive_public_key)
                .expect("internal error"),
            archive_kdf_key: KdfKey {
                key_key: rng.gen(),
                nonce_key: rng.gen(),
            },
            archive_hmac_key: rng.gen(),

            archive_name_id_key: rng.gen(),
            archive_name_kdf_key: KdfKey {
                key_key: rng.gen(),
                nonce_key: rng.gen(),
            },
            archive_name_hmac_key: rng.gen(),
        }
    }

    pub fn save<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        try!(write!(writer, "{}", self.as_pretty_json()));
        Ok(())
    }

    pub fn as_pretty_json(&self) -> String {
        format!("{}", json::as_pretty_json(&self))
    }

    pub fn load_from_vault(config_dir: Option<PathBuf>) -> Result<KeyStore> {
        let vault_config: VaultConfig = match config_dir {
            Some(config) => {
                // If --configdir was specified we use that as the base path
                info!("Reading vault config file: {}/{}",
                      config.display(),
                      "vault.json");
                let mut f = try!(File::open(config.join("vault.json")));
                let mut s = String::new();
                try!(f.read_to_string(&mut s));
                try!(json::decode(&s))
            }
            None => {
                // Otherwise we fallback on the $HOME as the base path
                info!("Reading vault config file: {}/{}",
                      home_dir().unwrap().to_string_lossy(),
                      ".config/vault.json");
                let mut f = try!(File::open(format!("{}/{}",
                                                    home_dir().unwrap().to_string_lossy(),
                                                    ".config/vault.json")));
                let mut s = String::new();
                try!(f.read_to_string(&mut s));
                try!(json::decode(&s))
            }
        };
        let client = try!(Client::new(&vault_config.host, &vault_config.token));
        let secret_64 = try!(client.get_secret("backup_key"));
        let decoded_64_vec = secret_64.from_base64().unwrap();
        let decoded_64 = try!(String::from_utf8(decoded_64_vec));
        Ok(try!(json::decode(&decoded_64)))
    }

    pub fn load<R: io::Read>(reader: &mut R) -> Result<KeyStore> {
        let mut data = String::new();
        try!(reader.read_to_string(&mut data));
        Ok(try!(json::decode(&data)))
    }

    pub fn load_from_path<P: AsRef<Path>>(path: P) -> Result<KeyStore> {
        let file = try!(fs::File::open(path));
        let mut reader = BufReader::new(file);

        KeyStore::load(&mut reader)
    }

    /// The maximum supported name is 127 bytes long (UTF-8 encoded).
    /// Encrypted file names will never exceed 255 bytes.
    /// Encrypted file names are base64 encoded.
    /// The underlying data is completely opaque (hmac + cipthertext + hmac)
    /// Encrypted file names are deterministic, i.e. the same name fed into this function will
    /// always return the same result (with respect to the KeyStore).
    pub fn encrypt_archive_name(&self, name: &str) -> Result<EncryptedArchiveName> {
        let plaintext = name.as_bytes();

        if plaintext.len() >= 128 {
            return Err(Error::ArchiveNameTooLong);
        }

        let id = Secret::from_slice(hmac(&self.archive_name_id_key, plaintext).code())
            .expect("internal error");
        let encryption_key = kdf(&self.archive_name_kdf_key, &id);
        let ciphertext = encrypt(&encryption_key, plaintext);

        let mut payload = vec![0u8; 0];
        payload.extend_from_slice(&id[..]);
        payload.extend_from_slice(&ciphertext);
        let mac = hmac(&self.archive_name_hmac_key, &payload).code().to_vec();

        payload.extend_from_slice(&mac);

        Ok(EncryptedArchiveName(payload))
    }

    pub fn decrypt_archive_name(&self,
                                &EncryptedArchiveName(ref payload): &EncryptedArchiveName)
                                -> Result<String> {
        if payload.len() < (32 + 32) {
            return Err(Error::CorruptArchiveName);
        }

        let payload = {
            let mac = MacResult::new(&payload[payload.len() - 32..]);
            let calculated_hmac = hmac(&self.archive_name_hmac_key, &payload[..payload.len() - 32]);

            if calculated_hmac != mac {
                return Err(Error::CorruptArchiveName);
            }

            &payload[..payload.len() - 32]
        };

        let id = Secret::from_slice(&payload[..32]).expect("internal error");
        let encryption_key = kdf(&self.archive_name_kdf_key, &id);
        let ciphertext = &payload[32..];

        let plaintext = encrypt(&encryption_key, ciphertext);

        String::from_utf8(plaintext).map_err(|_| Error::CorruptArchiveName)
    }

    pub fn encrypt_archive(&self,
                           &EncryptedArchiveName(ref encrypted_archive_name): &EncryptedArchiveName,
                           archive: &[u8])
                           -> EncryptedArchive {
        let ephemeral_private_key: Curve25519PrivateKey = {
            let mut rng = OsRng::new().expect("OsRng failed to initialize");
            rng.gen()
        };
        let ephemeral_public_key = Curve25519PublicKey::from_slice(
			&curve25519::curve25519_base(&ephemeral_private_key[..])).expect("internal error");

        let encryption_key = {
            let shared_secret =
                Secret::from_slice(&curve25519::curve25519(&ephemeral_private_key[..],
                                                           &self.archive_public_key[..]))
                    .expect("internal error");
            kdf(&self.archive_kdf_key, &shared_secret)
        };

        let ciphertext = encrypt(&encryption_key, archive);

        let mut payload = vec![0u8; 0];
        payload.extend_from_slice(&ephemeral_public_key[..]);
        payload.extend_from_slice(&ciphertext);

        let mac = {
            let mut buffer = vec![0u8; 0];
            buffer.extend_from_slice(encrypted_archive_name);
            buffer.extend_from_slice(&payload);
            hmac(&self.archive_hmac_key, &buffer).code().to_vec()
        };

        payload.extend_from_slice(&mac);
        EncryptedArchive(payload)
    }

    pub fn decrypt_archive(&self,
                           &EncryptedArchiveName(ref encrypted_archive_name): &EncryptedArchiveName,
                           &EncryptedArchive(ref payload): &EncryptedArchive)
                           -> Result<Vec<u8>> {
        // TODO: Nasty fat constants
        if payload.len() < 64 {
            return Err(Error::CorruptArchiveTruncated);
        }

        let calculated_mac = {
            let mut buffer = vec![0u8; 0];
            buffer.extend_from_slice(&encrypted_archive_name);
            buffer.extend_from_slice(&payload[..payload.len() - 32]);
            hmac(&self.archive_hmac_key, &buffer)
        };

        if calculated_mac != MacResult::new(&payload[payload.len() - 32..]) {
            return Err(Error::CorruptArchiveBadHmac);
        }

        let ephemeral_public_key = &payload[..32];
        let ciphertext = &payload[32..payload.len() - 32];

        let encryption_key = {
            let shared_secret =
                Secret::from_slice(&curve25519::curve25519(&self.archive_private_key[..],
                                                           &ephemeral_public_key))
                    .expect("internal error");
            kdf(&self.archive_kdf_key, &shared_secret)
        };

        let plaintext = encrypt(&encryption_key, ciphertext);

        Ok(plaintext)
    }

    pub fn block_id_from_block_secret(&self, block_secret: &Secret) -> BlockId {
        BlockId::from_slice(hmac(&self.block_id_key, &block_secret[..]).code())
            .expect("internal error")
    }

    pub fn block_secret_from_block(&self, block: &[u8]) -> Secret {
        Secret::from_slice(hmac(&self.block_secret_key, block).code()).expect("internal error")
    }

    pub fn encrypt_block(&self, id: &BlockId, secret: &Secret, block: &[u8]) -> EncryptedBlock {
        let encryption_key = kdf(&self.block_kdf_key, &secret);
        let ciphertext = encrypt(&encryption_key, block);

        let mac = {
            let mut buffer = vec![0u8; 0];
            buffer.extend_from_slice(&id[..]);
            buffer.extend_from_slice(&ciphertext);
            hmac(&self.block_hmac_key, &buffer).code().to_vec()
        };

        let mut payload = vec![0u8; 0];
        payload.extend_from_slice(&ciphertext);
        payload.extend_from_slice(&mac);

        EncryptedBlock(payload)
    }

    pub fn verify_encrypted_block(&self, id: &BlockId, encrypted_block: &EncryptedBlock) -> bool {
        let &EncryptedBlock(ref payload) = encrypted_block;

        // encrypted_block should at least contain a 32-byte MAC
        if payload.len() < 32 {
            return false;
        }

        let calculated_mac = {
            let mut buffer = vec![0u8; 0];
            buffer.extend_from_slice(&id[..]);
            buffer.extend_from_slice(&payload[..payload.len() - 32]);
            hmac(&self.block_hmac_key, &buffer)
        };

        MacResult::new(&payload[payload.len() - 32..]) == calculated_mac
    }

    pub fn decrypt_block(&self,
                         secret: &Secret,
                         id: &BlockId,
                         encrypted_block: &EncryptedBlock)
                         -> Result<Vec<u8>> {
        let &EncryptedBlock(ref payload) = encrypted_block;

        // Verify the block's authenticity and integrity
        if !self.verify_encrypted_block(id, encrypted_block) {
            return Err(Error::CorruptBlock);
        }

        let encryption_key = kdf(&self.block_kdf_key, secret);
        let ciphertext = &payload[..payload.len() - 32];
        let plaintext = encrypt(&encryption_key, ciphertext);

        Ok(plaintext)
    }
}


impl ToString for EncryptedArchiveName {
    fn to_string(&self) -> String {
        let &EncryptedArchiveName(ref payload) = self;

        payload[..].to_base64(base64::Config {
            char_set: base64::CharacterSet::UrlSafe,
            newline: base64::Newline::LF,
            pad: true,
            line_length: None,
        })
    }
}


impl FromStr for EncryptedArchiveName {
    type Err = FromBase64Error;

    fn from_str(s: &str) -> ::std::result::Result<EncryptedArchiveName, Self::Err> {
        Ok(EncryptedArchiveName(try!(s.from_base64())))
    }
}


impl ToString for BlockId {
    fn to_string(&self) -> String {
        let &BlockId(ref id) = self;

        id.to_hex().to_lowercase()
    }
}


fn hmac(key: &HmacKey, data: &[u8]) -> MacResult {
    let mut hmac = Hmac::new(Sha256::new(), &key[..]);
    hmac.input(data);
    hmac.result()
}


fn kdf(kdf_key: &KdfKey, secret: &Secret) -> EncryptionKey {
    EncryptionKey {
        key: ChaCha20Key::from_slice(hmac(&kdf_key.key_key, &secret[..]).code())
            .expect("internal error"),
        nonce: ChaCha20Nonce::from_slice(&hmac(&kdf_key.nonce_key, &secret[..]).code()[0..8])
            .expect("internal error"),
    }
}


fn encrypt(key: &EncryptionKey, data: &[u8]) -> Vec<u8> {
    let mut encryptor = ChaCha20::new(&key.key[..], &key.nonce[..]);
    let mut output = vec!(0u8; data.len());
    encryptor.process(data, &mut output);
    output
}


#[cfg(test)]
mod test {
    use super::{HmacKey, KdfKey, Secret, ChaCha20Key, ChaCha20Nonce, EncryptionKey, KeyStore,
                EncryptedArchiveName, EncryptedArchive, BlockId, EncryptedBlock, hmac, kdf,
                encrypt};
    use rustc_serialize::hex::FromHex;
    use rustc_serialize::json;
    use crypto::mac::MacResult;
    use std::io::Cursor;
    use crypto::curve25519::curve25519_base;
    use std::str::FromStr;


    #[test]
    fn test_hmac() {
        // Test vector generated manually using Python
        let key = HmacKey::from_slice(&"ffb5dcc86e1eb427a405d9a038e8db18f6e1ff0f335288143f77f708e2
c7f524fca279a5242e616b45c28913356575768d0077d51ab8550f5264a0368def5f0a"
                .from_hex()
                .unwrap())
            .unwrap();
        let data = "896af71f4f51c8a6dc32357d407a01d15fdc5fd05b2c73d9c4c5e5bd14cae7c58661fcfe39da3
8ac0a956befec7fc3fe437f5243acbfe8d0412cbe7fa3c1547ff91764cb5be8ade347386bfd630a5fae08c139cd
2fc58fb11542e56d94817f44bc79b40ba4fef1c8ee7709c77ab2399d8419fe8017439da3"
            .from_hex()
            .unwrap();
        let expected =
            "9d4e17e1d5842c289a78c03da7218e85683c5842d6f4367dd2fab79da1d0464b".from_hex().unwrap();

        assert!(hmac(&key, &data) == MacResult::new(&expected));
    }

    #[test]
    fn test_kdf() {
        // Test vector generated manually using Python
        let kdf_key = KdfKey {
            key_key: HmacKey::from_slice(&"32fb9afd920064555d403ffd11bb4f37870c67bc30595cac6613b
c9e8e46b50335b8bedc478757b8d148d064475e8124083b1c311e29411d491e087680844f01"
                    .from_hex()
                    .unwrap())
                .unwrap(),
            nonce_key: HmacKey::from_slice(&"9fa40dbab494f0c154eef8f0dadf5e4df527d2972cacfd80
0002b6f8db7975942a2e6f35d7f394fcfe6ce3744bdb6f1f423a65fa7b6aab70e4f66e274e24261e"
                    .from_hex()
                    .unwrap())
                .unwrap(),
        };
        let secret = Secret::from_slice(&"d0dbfab271e591ef9745e33b4a18edcac29513afd79cbba4
fc8581037985128c"
                .from_hex()
                .unwrap())
            .unwrap();
        let expected_key = ChaCha20Key::from_slice(&"8ec2bd8afb3c8fea1b7aa09f813c3df2488fd
79c635111e2b7c490217759bef6"
                .from_hex()
                .unwrap())
            .unwrap();
        let expected_nonce = ChaCha20Nonce::from_slice(&"7f73a2dae4d687a0".from_hex().unwrap())
            .unwrap();
        let output = kdf(&kdf_key, &secret);

        assert_eq!(output.key, expected_key);
        assert_eq!(output.nonce, expected_nonce);
    }

    #[test]
    fn test_encrypt() {
        // https://github.com/secworks/chacha_testvectors/blob/master/src/chacha_testvectors.txt
        // with random data XOR'd in Python
        let encryption_key = EncryptionKey {
            key: ChaCha20Key::from_slice(&"00112233445566778899aabbccddeeffffeeddccbbaa99887766
554433221100 "
                    .from_hex()
                    .unwrap())
                .unwrap(),
            nonce: ChaCha20Nonce::from_slice(&"0f1e2d3c4b5a6978".from_hex().unwrap()).unwrap(),
        };
        let data = "aa8ba6688d21ace02dd33078a3b4bf36512ec1c5516dfee2465a4d81d84efec106f5acab2b
9c3d14e19a23bd9d8935a720639bdea7f4e9ac2de69efbc17e95185f2b2fd12039"
            .from_hex()
            .unwrap();
        let expected = "352652614d29bd3029e2e606586c308c080f4c9836654f34c3dc722a634068dfecbda37
dd0cf16e9a8d102ec9cd962e51ad591bd59bbbc5b8ff47cedbdb42c29a4d6061e5bf8"
            .from_hex()
            .unwrap();
        let output = encrypt(&encryption_key, &data);

        assert_eq!(output, expected);
    }

    // Test vector generated manually using Python
    const TEST_KEYSTORE_JSON: &'static str = include!("../tests/test_keystore.json");

    /// Test if the public key from the test vector is correct
    #[test]
    fn test_keystore_public_key() {
        let keystore: KeyStore = json::decode(TEST_KEYSTORE_JSON).unwrap();
        let output_public_key = curve25519_base(&keystore.archive_private_key[..]);

        assert_eq!(output_public_key, keystore.archive_public_key[..]);
    }

    #[test]
    fn test_keystore_save_load() {
        let keystore: KeyStore = json::decode(TEST_KEYSTORE_JSON).unwrap();
        let mut buffer = vec![0u8; 0];

        keystore.save(&mut buffer).unwrap();
        let output = KeyStore::load(&mut Cursor::new(buffer)).unwrap();

        assert_eq!(output, keystore);
    }

    #[test]
    fn test_encrypt_archive_name() {
        let keystore: KeyStore = json::decode(TEST_KEYSTORE_JSON).unwrap();
        let name = "(╯°□°）╯︵ ┻━┻";
        let expected = format!("{}{}",
                               "YuDnnmapCAOdv9RfpB77aVAln9NWgK9maOkpO4omqQvc9Dnng26-IH_qz",
                               "iHcxAMofqG1uGfMt2_Z4LkQdO_zXcmRn_6NY0FS3U_uSAGmudueq_r5H37QDYXQJIcV_A==");
        let output = keystore.encrypt_archive_name(name).unwrap().to_string();

        assert_eq!(output, expected);
    }

    #[test]
    fn test_decrypt_archive_name() {
        let keystore: KeyStore = json::decode(TEST_KEYSTORE_JSON).unwrap();
        let name = "YuDnnmapCAOdv9RfpB77aVAln9NWgK9maOkpO4omqQvc9Dnng26-IH_qziHcxAMofqG1uGfMt
2_Z4LkQdO_zXcmRn_6NY0FS3U_uSAGmudueq_r5H37QDYXQJIcV_A==";
        let expected = "(╯°□°）╯︵ ┻━┻";
        let output = keystore.decrypt_archive_name(&EncryptedArchiveName::from_str(name).unwrap())
            .unwrap();

        assert_eq!(output, expected);
    }

    #[test]
    fn encrypt_archive() {
        let keystore: KeyStore = json::decode(TEST_KEYSTORE_JSON).unwrap();
        let encrypted_name = EncryptedArchiveName("13230a254e27bac67067a5c3ead9539141ffe689cd60
6ce9f3baec4b3384743d59934754363eb00ffdb3d128b6b691004e6df66f17ad90dba6ff939417a920b08827b93a8ab7"
            .from_hex()
            .unwrap());
        let archive = "1c50fc6cff9174cdef6ae1949783cec449514818eb27ce9c1d0a475c23fb2a2de6741a9f
b0462516d1ee69e1b1f70d6e4aecf03d0ae7260d3728e5cbfde6e73cbd9178a4d1164d2469dcf72aa84b4aac9c442c2
018a4b6ef211cf49215f7a85fd27f13ae620347f2bd608b7550275cb9c51bbe52db156d8d75b27f9c16629f7fe6171a
ac7389c4f0dedc69c32b761fcb5974bdfd7661a98dae81c2becfde29fbb23d7a72ba5338ad6fd5fb56e1e3ee8dc0ed7
0bc054df683773c0001b2e51922ded5cf3908fb3769"
            .from_hex()
            .unwrap();

        let encrypted = keystore.encrypt_archive(&encrypted_name, &archive);
        let decrypted = keystore.decrypt_archive(&encrypted_name, &encrypted).unwrap();

        assert_eq!(decrypted, archive);
    }

    #[test]
    fn decrypt_archive() {
        let keystore: KeyStore = json::decode(TEST_KEYSTORE_JSON).unwrap();
        let encrypted_name = EncryptedArchiveName("13230a254e27bac67067a5c3ead9539141ffe689cd60
6ce9f3baec4b3384743d59934754363eb00ffdb3d128b6b691004e6df66f17ad90dba6ff939417a920b08827b93a8ab7"
            .from_hex()
            .unwrap());
        let encrypted = EncryptedArchive("29c12a136d3b0a86a580476bf683e2dccc11983aa1804972e122e
3aada7553329057064501290bc01157c515b0b6ab33cf16cd5526b01c4ce7a286e9b9aad32ab731719013709008d6e6
57975cab0db16050aeaf651f2400541a3f6ffdf868e2112191a421e86799cda25e47edf90eb43d257dc1d0f0a354844
6e8b4b3d753566cf997591118dfb5839fc26718a2bc8677b59a00060eb5de66392d0c352ec233d53548f6be012a202b
a1074fc95b2f1e4430eb18dc9cc52f817b652f88ec65465121501e790daa174cb1b982aaa4c0933ae7daccafa7b9571
109d2869256eee2b8404d43bc774a5b42b8e9939445d30560a4c0840786ebb5565c7a70663adc0bbbca3e6e1618ae14"
            .from_hex()
            .unwrap());
        let expected = "1c50fc6cff9174cdef6ae1949783cec449514818eb27ce9c1d0a475c23fb2a2de6741a9
		fb0462516d1ee69e1b1f70d6e4aecf03d0ae7260d3728e5cbfde6e73cbd9178a4d1164d2469dcf72aa84b4a
		ac9c442c2018a4b6ef211cf49215f7a85fd27f13ae620347f2bd608b7550275cb9c51bbe52db156d8d75b27
		f9c16629f7fe6171aac7389c4f0dedc69c32b761fcb5974bdfd7661a98dae81c2becfde29fbb23d7a72ba53
		38ad6fd5fb56e1e3ee8dc0ed70bc054df683773c0001b2e51922ded5cf3908fb3769"
            .from_hex()
            .unwrap();
        let output = keystore.decrypt_archive(&encrypted_name, &encrypted).unwrap();

        assert_eq!(output, expected);
    }

    #[test]
    fn block_id_from_block_secret() {
        let keystore: KeyStore = json::decode(TEST_KEYSTORE_JSON).unwrap();
        let secret =
            Secret::from_slice(&"2777f099df579d92a133c63b070e90336a603ed53dce96d6856365f8618e9597"
                    .from_hex()
                    .unwrap())
                .unwrap();
        let expected = "7b768a13e4fde76930e38c6eb7f83d320bddc5eecf8b5fe970543b7feea195dc";
        let output = keystore.block_id_from_block_secret(&secret);

        assert_eq!(output.to_string(), expected);
    }

    #[test]
    fn block_secret_from_block() {
        let keystore: KeyStore = json::decode(TEST_KEYSTORE_JSON).unwrap();
        let block = "a928fbcbcbe0fed28f942f97d0890efafb29134d8a32798f0919e9930c4481b4228114e37316
caab4844b54f2ae7b053f85fa36732bc2f8d64c240227a80d0a0d6f1aefc7c94cfc77657a2af1fb67f65e3c1e50dfb255
552f11187465e0cc2acb81f250a6577d50d828790b3f855395f28c0d9c23358d40a1fb84c8383226f740de67ebf24b975
c6972760895b46cc866aec410e7999a04232009c442a4d609c9df38f95de773c5b981344d3007e27b2b1eca1a42580a50
a08f6d550892e4b60a18223d0fc049fcd"
            .from_hex()
            .unwrap();
        let expected = Secret::from_slice(&"242d98aa50d8048bb1e4eed232cc7c0e23d7fdd8db2e01e7b2579
4acf0d850e7"
                .from_hex()
                .unwrap())
            .unwrap();
        let output = keystore.block_secret_from_block(&block);

        assert_eq!(output, expected);
    }

    #[test]
    fn encrypt_block() {
        let keystore: KeyStore = json::decode(TEST_KEYSTORE_JSON).unwrap();
        let block = "cc544b2050e96c38880414a54fcd22a7732438acc08b9541ef00621fae3fc4311ccacef1da70
36eb69116a297eca3f256a62e9f9c41d82794d975a7d7c9473df1887cd409c59fc3a564d8861a1fbe46e3b4393269ff0c
60406688a3ce27314c4dcc73e4e69521fe357235240f70fa80b16b8fcc8376340a64ddeb4c486b0a4363d0d90b35db981
1ca243a59f3582d8fcbf2fa95affdc8f8848ac0cbc43f4cb0d6a6240c6835e44014a4b178969ad76c8c7fb953450d4896
eb541fa5bbd20cb3cfcc681db7b46dd1d"
            .from_hex()
            .unwrap();
        let expected_secret = Secret::from_slice(&"ed10dd0d10371ceaaa1fb0c7aafe4c263ae63d3d121864
9dffa579b7e13a6cc3"
                .from_hex()
                .unwrap())
            .unwrap();
        let expected_id = BlockId::from_slice(&"8aa4569826e5c06fec4fd9bf30f9dba6a71678ed6c57761cc
1cc0173ce993eab"
                .from_hex()
                .unwrap())
            .unwrap();
        let expected_block = EncryptedBlock("5f61b5865df068f40a6092429b90c3849e0bc86f0048a5154173
97782e6b14a1d8e06a5408c0f7884b4c33850047c0ce4a1e648e51b6357fc6fb3fad19877ac169e1da21dd9af4b7f74f4
db86f993b4c7ac8454cee6274a54c38751bfd908e72b5663c1aaea63956f66017711850e7467cb485adce83943c4d0525
133567c7082d25eb739fc317037b91a691177dc5536e8b5d73d1b0345f5d587abf87bc228ffb0480c70ab9abd3f89006b
c788968e542f24f5f6b48ac8b80ff7e9045f061389b2b56a6a165fe245e1765decc85c1f24c2dcf493685dc071f0cdaba
c909680fcfd9d67001bf2b77"
            .from_hex()
            .unwrap()
            .to_vec());

        let secret = keystore.block_secret_from_block(&block);
        let id = keystore.block_id_from_block_secret(&secret);
        let encrypted = keystore.encrypt_block(&id, &secret, &block);

        assert_eq!(secret, expected_secret);
        assert_eq!(id, expected_id);
        assert_eq!(encrypted, expected_block);
    }

    #[test]
    fn test_verify_encrypted_block() {
        let keystore: KeyStore = json::decode(TEST_KEYSTORE_JSON).unwrap();
        let id = BlockId::from_slice(&"a174d2732f230ad12f43d82af279a49636236d26321be908116e386e7
ea1f737"
                .from_hex()
                .unwrap())
            .unwrap();
        let encrypted_block = EncryptedBlock("f96e286e89cfda5548d4a82d63b91db6c1d5731176b15a6205d
6dc274b322e261fe4eb8dc91418438d730839a4d097e768d5bd9b3f300180158fbd77428782ac87a3e5338561974ba043
4c38c660dc3d0d0e7bf7358c3372d313f3a1be5bdf46f08f60840bc264caed3a17064a3c21a8b1150f87361f4e389f4e1
87c86cd069f032a2f15"
            .from_hex()
            .unwrap()
            .to_vec());

        assert!(keystore.verify_encrypted_block(&id, &encrypted_block));
    }

    #[test]
    fn test_decrypt_block() {
        let keystore: KeyStore = json::decode(TEST_KEYSTORE_JSON).unwrap();
        let secret = Secret::from_slice(&"ed10dd0d10371ceaaa1fb0c7aafe4c263ae63d3d1218649dffa579
b7e13a6cc3"
                .from_hex()
                .unwrap())
            .unwrap();
        let encrypted_block = EncryptedBlock("5f61b5865df068f40a6092429b90c3849e0bc86f0048a515
417397782e6b14a1d8e06a5408c0f7884b4c33850047c0ce4a1e648e51b6357fc6fb3fad19877ac169e1da21dd9af4b7
f74f4db86f993b4c7ac8454cee6274a54c38751bfd908e72b5663c1aaea63956f66017711850e7467cb485adce83943c
4d0525133567c7082d25eb739fc317037b91a691177dc5536e8b5d73d1b0345f5d587abf87bc228ffb0480c70ab9abd3
f89006bc788968e542f24f5f6b48ac8b80ff7e9045f061389b2b56a6a165fe245e1765decc85c1f24c2dcf493685dc07
1f0cdabac909680fcfd9d67001bf2b77"
            .from_hex()
            .unwrap()
            .to_vec());
        let expected = "cc544b2050e96c38880414a54fcd22a7732438acc08b9541ef00621fae3fc4311ccac
ef1da7036eb69116a297eca3f256a62e9f9c41d82794d975a7d7c9473df1887cd409c59fc3a564d8861a1fbe46e3b43
93269ff0c60406688a3ce27314c4dcc73e4e69521fe357235240f70fa80b16b8fcc8376340a64ddeb4c486b0a4363d0
d90b35db9811ca243a59f3582d8fcbf2fa95affdc8f8848ac0cbc43f4cb0d6a6240c6835e44014a4b178969ad76c8c7
fb953450d4896eb541fa5bbd20cb3cfcc681db7b46dd1d"
            .from_hex()
            .unwrap();

        let id = keystore.block_id_from_block_secret(&secret);
        let output = keystore.decrypt_block(&secret, &id, &encrypted_block).unwrap();

        assert_eq!(output, expected);
    }
}
