use crate::backend::Backend;
use crate::keystore::{ArchiveId, EncryptedArchiveName, EncryptedArchiveMetadata, EncryptedBlock, BlockId};
use std::path::{Path, PathBuf};
use std::io::{Read, Write};
use std::fs::{self, OpenOptions};
use rand::rngs::OsRng;
use rand::Rng;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::str::FromStr;
use crate::error::*;


pub struct FileBackend {
	backup_dir: PathBuf,
}

impl FileBackend {
	pub fn new<P: AsRef<Path>>(backup_dir: P) -> FileBackend {
		FileBackend {
			backup_dir: backup_dir.as_ref().to_path_buf(),
		}
	}

	fn safely_write_file<P: AsRef<Path>>(&self, destination: P, data: &[u8]) -> Result<()> {
		// First, write to a temporary file.
		let temppath = {
			let mut rng = OsRng::new().expect("OsRng failed during initialization");
			let tempname: String = rng.sample_iter(&rand::distributions::Alphanumeric).take(32).collect();
			let temppath = self.backup_dir.join("temp");
			fs::create_dir_all(&temppath).unwrap_or(());
			temppath.join(tempname)
		};

		{
			let mut file = OpenOptions::new().write(true).create(true).open(&temppath)?;

			file.write_all(data)?;
		}

		// Archives and Blocks should be stored as world readonly
		fs::set_permissions(&temppath, PermissionsExt::from_mode(0o444))?;

		// Ensure that temppath and the destination are both on the same device so that rename
		// below is an atomic move operation, rather than a copy.
		{
			let temppath_metadata = temppath.metadata()?;
			let destination_parent = destination.as_ref().parent().ok_or(Error::BackendOnDifferentDevices)?;
			let destination_parent_metadata = destination_parent.metadata()?;
			if temppath_metadata.dev() != destination_parent_metadata.dev() {
				return Err(Error::BackendOnDifferentDevices);
			}
		}

		// Then move the file to its final destination.  This avoids any truncation in case of early
		// termination/crash.
		fs::rename(temppath, destination)?;

		Ok(())
	}
}

impl Backend for FileBackend {
	fn block_exists(&mut self, id: &BlockId) -> Result<bool> {
		let block_id = id.to_string();
		let dir1 = &block_id[0..2];
		let dir2 = &block_id[2..4];

		let path = self.backup_dir.join("blocks").join(dir1).join(dir2).join(&block_id);

		Ok(path.exists())
	}

	fn store_block(&mut self, id: &BlockId, data: &EncryptedBlock) -> Result<()> {
		let block_id = id.to_string();
		let dir1 = &block_id[0..2];
		let dir2 = &block_id[2..4];

		let path = {
			let path = self.backup_dir.join("blocks").join(dir1).join(dir2);
			fs::create_dir_all(&path).unwrap_or(());
			path.join(&block_id)
		};

		if path.exists() {
			return Ok(());
		}

		self.safely_write_file(path, &data.0)
	}

	fn fetch_block(&mut self, id: &BlockId) -> Result<EncryptedBlock> {
		let block_id = id.to_string();
		let dir1 = &block_id[0..2];
		let dir2 = &block_id[2..4];

		let path = self.backup_dir.join("blocks").join(dir1).join(dir2).join(&block_id);
		let mut file = fs::File::open(path)?;

		let mut ciphertext = Vec::<u8>::new();

		file.read_to_end(&mut ciphertext)?;

		Ok(EncryptedBlock(ciphertext))
	}

	fn fetch_archive(&mut self, id: &ArchiveId) -> Result<EncryptedArchiveMetadata> {
		let path = self.backup_dir.join("archives").join(format!("{}.metadata", id.to_string()));

		let data = fs::read(path)?;

		Ok(EncryptedArchiveMetadata(data))
	}

	fn store_archive(&mut self, id: &ArchiveId, name: &EncryptedArchiveName, data: &EncryptedArchiveMetadata) -> Result<()> {
		let name_path = self.backup_dir.join("archives").join(format!("{}.name", id.to_string()));
		let metadata_path = self.backup_dir.join("archives").join(format!("{}.metadata", id.to_string()));
		fs::create_dir_all(&self.backup_dir.join("archives")).unwrap_or(());

		// TODO: Right now there is a race condition here.  This will be fixed in the future when we add a SQLite database for managing refcounts and other atomic things.
		if name_path.exists() {
			return Err(Error::ArchiveNameConflict);
		}

		self.safely_write_file(name_path, &name.0)?;
		self.safely_write_file(metadata_path, &data.0)
	}

	fn list_archives(&mut self) -> Result<Vec<(ArchiveId, EncryptedArchiveName)>> {
		let mut archives = Vec::new();

		for entry in fs::read_dir(self.backup_dir.join("archives"))? {
			let path = entry?.path();

			let extension = path.extension().ok_or(Error::InvalidArchiveId)?;
			if extension != "name" {
				continue;
			}

			let filename = path.file_stem().ok_or(Error::InvalidArchiveId)?;
			let filename_str = filename.to_str().ok_or(Error::InvalidArchiveId)?;
			let archive_id = ArchiveId::from_str(filename_str).map_err(|_| Error::InvalidArchiveId)?;
			let data = fs::read(path)?;
			let encrypted_archive_name = EncryptedArchiveName(data);

			archives.push((archive_id, encrypted_archive_name));
		}

		Ok(archives)
	}
}
