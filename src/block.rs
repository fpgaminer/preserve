use keystore::{KeyStore, Secret};
use backend::Backend;
use error::*;


pub struct BlockStore<'a> {
	keystore: &'a KeyStore,
}


impl<'a> BlockStore<'a> {
	pub fn new(keys: &'a KeyStore) -> BlockStore<'a> {
		BlockStore {
			keystore: keys,
		}
	}

	pub fn block_exists(&self, secret: &Secret, backend: &mut Backend) -> Result<bool> {
		let block_id = self.keystore.block_id_from_block_secret(secret);
		backend.block_exists(&block_id)
	}

	pub fn new_block_from_plaintext(&self, plaintext: &[u8], backend: &mut Backend) -> Result<Secret> {
		let block_secret = self.keystore.block_secret_from_block(plaintext);
		let block_id = self.keystore.block_id_from_block_secret(&block_secret);

		if backend.block_exists(&block_id)? {
			return Ok(block_secret);
		}

		let encrypted_block = self.keystore.encrypt_block(&block_id, &block_secret, plaintext);

		backend.store_block(&block_id, &encrypted_block)?;

		Ok(block_secret)
	}

	pub fn fetch_block(&self, secret: &Secret, backend: &mut Backend) -> Result<Vec<u8>> {
		let block_id = self.keystore.block_id_from_block_secret(secret);
		let encrypted_block = backend.fetch_block(&block_id)?;

		self.keystore.decrypt_block(secret, &block_id, &encrypted_block)
	}
}
