extern crate gfapi_sys;

use std::env::home_dir;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use self::gfapi_sys::gluster::{Gluster, GlusterDirectory};

use backend::Backend;
use clap::ArgMatches;
use keystore::{EncryptedArchiveName, EncryptedArchive, EncryptedBlock, BlockId};
use libc::{O_RDONLY, O_WRONLY};
use rustc_serialize::json;
use error::*;


pub struct GlusterBackend {
    gluster: Gluster,
}

#[derive(RustcDecodable)]
struct GlusterConfig {
    /// The DNS or IP address of the server to connect to
    server: String,
    /// The server port to connect to.  Usually 24007
    port: u16,
    /// Which Gluster volume to connect to
    volume_name: String,
}

impl GlusterBackend {
    pub fn new(config_dir: Option<PathBuf>) -> Result<GlusterBackend> {
        let gluster_config: GlusterConfig = match config_dir {
            Some(config) => {
                // If --configdir was specified we use that as the base path
                info!("Reading gluster config file: {}/{}",
                      config.display(),
                      "gluster.json");
                let mut f = try!(File::open(config.join("gluster.json")));
                let mut s = String::new();
                try!(f.read_to_string(&mut s));
                try!(json::decode(&s))
            }
            None => {
                // Otherwise we fallback on the $HOME as the base path
                info!("Reading gluster config file: {}/{}",
                      home_dir().unwrap().to_string_lossy(),
                      ".config/ceph.json");
                let mut f = try!(File::open(format!("{}/{}",
                                                    home_dir().unwrap().to_string_lossy(),
                                                    ".config/gluster.json")));
                let mut s = String::new();
                try!(f.read_to_string(&mut s));
                try!(json::decode(&s))
            }
        };

        info!("Connecting to Gluster");
        let gluster_handle = try!(Gluster::connect(&gluster_config.volume_name,
                                                   &gluster_config.server,
                                                   gluster_config.port));
        info!("Connection to Gluster established");
        Ok(GlusterBackend { gluster: gluster_handle })
    }
}

impl Backend for GlusterBackend {
    fn block_exists(&mut self, id: &BlockId) -> Result<bool> {
        let block_id = id.to_string();
        let dir1 = &block_id[0..2];
        let dir2 = &block_id[2..4];

        let path = PathBuf::from("/blocks").join(dir1).join(dir2).join(&block_id);
        match self.gluster.stat(&path.as_path()) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn store_block(&mut self,
                   id: &BlockId,
                   &EncryptedBlock(ref data): &EncryptedBlock)
                   -> Result<()> {
        let block_id = id.to_string();
        let dir1 = &block_id[0..2];
        let dir2 = &block_id[2..4];

        let path = PathBuf::from("/blocks").join(dir1).join(dir2).join(&block_id);
        try!(self.gluster.mkdir(Path::new("/blocks"), 0755));
        debug!("Created directory /blocks");
        try!(self.gluster.mkdir(&Path::new(&format!("/blocks/{}", dir1)), 0755));
        debug!("Created directory /blocks/{}", dir1);
        try!(self.gluster.mkdir(&Path::new(&format!("/blocks/{}/{}", dir1, dir2)), 0755));
        debug!("Created directory /blocks/{}/{}", dir1, dir2);

        let file_handle = try!(self.gluster.create(path.as_path(), O_WRONLY, 0755));
        let write_size = try!(self.gluster.write(file_handle, &data, 0));
        debug!("wrote {} bytes to {:?}", write_size, path);

        try!(self.gluster.close(file_handle));
        Ok(())
    }

    fn fetch_block(&mut self, id: &BlockId) -> Result<EncryptedBlock> {
        let block_id = id.to_string();
        let dir1 = &block_id[0..2];
        let dir2 = &block_id[2..4];

        let path = PathBuf::from("/blocks").join(dir1).join(dir2).join(&block_id);
        let file_handle = try!(self.gluster.open(path.as_path(), O_RDONLY));

        // Blocks are 1MB so this should be plenty
        let capacity: usize = 1024 * 1024 * 2;
        let mut ciphertext = Vec::<u8>::with_capacity(capacity);
        try!(self.gluster.read(file_handle, &mut ciphertext, capacity, 0));
        try!(self.gluster.close(file_handle));

        Ok(EncryptedBlock(ciphertext))
    }

    fn fetch_archive(&mut self, name: &EncryptedArchiveName) -> Result<EncryptedArchive> {
        let path = PathBuf::from("/archives").join(name.to_string());
        let file_handle = try!(self.gluster.open(path.as_path(), O_RDONLY));

        let mut buffer: Vec<u8> = Vec::new();
        // Read 1MB at a time
        let capacity: usize = 1024 * 1024;
        loop {
            let mut tmp_buffer = Vec::<u8>::with_capacity(capacity);
            let read_size = try!(self.gluster.read(file_handle, &mut tmp_buffer, capacity, 0));
            if read_size <= 0 {
                break;
            }
            buffer.extend_from_slice(&tmp_buffer);
        }
        try!(self.gluster.close(file_handle));

        Ok(EncryptedArchive(buffer))
    }

    fn store_archive(&mut self,
                     name: &EncryptedArchiveName,
                     &EncryptedArchive(ref payload): &EncryptedArchive)
                     -> Result<()> {
        let path = {
            let path = PathBuf::from("/archives");
            fs::create_dir_all(&path).unwrap_or(());
            path.join(name.to_string())
        };
        try!(self.gluster.mkdir(Path::new("/archives"), 0755));
        debug!("Created directory /archives");
        let file_handle = try!(self.gluster.create(path.as_path(), O_WRONLY, 0755));
        let write_size = try!(self.gluster.write(file_handle, &payload, 0));
        debug!("wrote {} bytes to {:?}", write_size, path);
        try!(self.gluster.close(file_handle));
        Ok(())
    }

    fn list_archives(&mut self) -> Result<Vec<EncryptedArchiveName>> {
        let mut archives = Vec::new();

        let archive_dir =
            GlusterDirectory { dir_handle: try!(self.gluster.opendir(Path::new("/archives"))) };
        let dot = Path::new(".");
        let dot_dot = Path::new("..");
        for entry in archive_dir {
            if entry.path == dot || entry.path == dot_dot {
                continue;
            }
            // If we can't turn the filename into a string skip it
            if let Some(filename) = entry.path.to_str() {
                let encrypted_archive_name = try!(EncryptedArchiveName::from_str(filename)
                    .map_err(|_| Error::InvalidArchiveName));
                archives.push(encrypted_archive_name);
            }
        }
        Ok(archives)
    }
}
