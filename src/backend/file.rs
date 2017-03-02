use backend::Backend;
use keystore::{EncryptedArchiveName, EncryptedArchive, EncryptedBlock, BlockId};
use std::path::{Path, PathBuf};
use std::io::{BufReader, Read, Write};
use std::fs::{self, OpenOptions};
use rand::{Rng, OsRng};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::str::FromStr;
use error::*;


pub struct FileBackend {
    backup_dir: PathBuf,
}

impl FileBackend {
    pub fn new<P: AsRef<Path>>(backup_dir: P) -> FileBackend {
        FileBackend { backup_dir: backup_dir.as_ref().to_path_buf() }
    }

    fn safely_write_file<P: AsRef<Path>>(&self, destination: P, data: &[u8]) -> Result<()> {
        // First, write to a temporary file.
        let temppath = {
            let mut rng = OsRng::new().expect("OsRng failed during initialization");
            let tempname: String = rng.gen_ascii_chars().take(25).collect();
            let temppath = self.backup_dir.join("temp");
            fs::create_dir_all(&temppath).unwrap_or(());
            temppath.join(tempname)
        };

        {
            let mut file = try!(OpenOptions::new().write(true).create(true).open(&temppath));

            try!(file.write_all(data));
        }

        // Archives and Blocks should be stored as world readonly
        try!(fs::set_permissions(&temppath, PermissionsExt::from_mode(0o444)));

        // Ensure that temppath and the destination are both on the same device so that rename
        // below is an atomic move operation, rather than a copy.
        {
            let temppath_metadata = try!(temppath.metadata());
            let destination_parent =
                try!(destination.as_ref().parent().ok_or(Error::BackendOnDifferentDevices));
            let destination_parent_metadata = try!(destination_parent.metadata());
            if temppath_metadata.dev() != destination_parent_metadata.dev() {
                return Err(Error::BackendOnDifferentDevices);
            }
        }

        // Then move the file to its final destination.  This avoids any truncation in case of early
        // termination/crash.
        try!(fs::rename(temppath, destination));

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

    fn store_block(&mut self,
                   id: &BlockId,
                   &EncryptedBlock(ref data): &EncryptedBlock)
                   -> Result<()> {
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

        self.safely_write_file(path, data)
    }

    fn fetch_block(&mut self, id: &BlockId) -> Result<EncryptedBlock> {
        let block_id = id.to_string();
        let dir1 = &block_id[0..2];
        let dir2 = &block_id[2..4];

        let path = self.backup_dir.join("blocks").join(dir1).join(dir2).join(&block_id);
        let mut file = try!(fs::File::open(path));

        let mut ciphertext = Vec::<u8>::new();

        try!(file.read_to_end(&mut ciphertext));

        Ok(EncryptedBlock(ciphertext))
    }

    fn fetch_archive(&mut self, name: &EncryptedArchiveName) -> Result<EncryptedArchive> {
        let path = self.backup_dir.join("archives").join(name.to_string());

        let mut buffer = vec![0u8; 0];
        let mut reader = BufReader::new(try!(fs::File::open(path)));

        try!(reader.read_to_end(&mut buffer));
        Ok(EncryptedArchive(buffer))
    }

    fn store_archive(&mut self,
                     name: &EncryptedArchiveName,
                     &EncryptedArchive(ref payload): &EncryptedArchive)
                     -> Result<()> {
        let path = {
            let path = self.backup_dir.join("archives");
            fs::create_dir_all(&path).unwrap_or(());
            path.join(name.to_string())
        };

        if path.exists() {
            return Err(Error::ArchiveNameConflict);
        }

        self.safely_write_file(path, payload)
    }

    fn list_archives(&mut self) -> Result<Vec<EncryptedArchiveName>> {
        let mut archives = Vec::new();

        for entry in try!(fs::read_dir(self.backup_dir.join("archives"))) {
            let entry = try!(entry);
            let filename = entry.file_name();
            let filename_str = try!(filename.to_str().ok_or(Error::InvalidArchiveName));
            let encrypted_archive_name = try!(EncryptedArchiveName::from_str(filename_str)
                .map_err(|_| Error::InvalidArchiveName));

            archives.push(encrypted_archive_name);
        }

        Ok(archives)
    }
}
