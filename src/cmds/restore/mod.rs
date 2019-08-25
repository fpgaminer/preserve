use crate::keystore::{KeyStore, BlockId};
use std::fs;
use std::io::{self, BufWriter, Write, Read};
use std::path::{Path, PathBuf};
use std::os::unix::fs::PermissionsExt;
use std::collections::HashMap;
use crate::backend::{self, Backend};
use crate::archive::{Archive, File};
use clap::ArgMatches;
use crate::error::*;
use log::{error, info};


struct DownloadCache {
	refcount: u64,
	downloaded: bool,
	id: BlockId,
}


pub fn execute(args: &ArgMatches) {
	let debug_decrypt = args.is_present("debug-decrypt");

	if !debug_decrypt && !args.is_present("PATH") {
		error!("Missing <PATH> option");
		return;
	}

	let args_keyfile = args.value_of("keyfile").expect("internal error");
	let args_backend = args.value_of("backend").expect("internal error");
	let backup_name = args.value_of("NAME").expect("internal error");
	let target_directory = match args.value_of("PATH") {
		Some(path) => match Path::new(path).canonicalize() {
			Ok(path) => path,
			Err(err) => {
				error!("Unable to find the destination path: {}", err);
				return;
			},
		},
		None => PathBuf::new(),
	};

	let keystore = match KeyStore::load_from_path(args_keyfile) {
		Ok(keystore) => keystore,
		Err(err) => {
			error!("Unable to load keyfile: {}", err);
			return;
		}
	};

	let mut backend = match backend::backend_from_backend_path(args_backend) {
		Ok(backend) => backend,
		Err(err) => {
			error!("Unable to load backend: {}", err);
			return;
		}
	};

	let mut config = Config::default();

	config.dereference_hardlinks = args.is_present("hard-dereference");

	let (archive_id, _) = keystore.encrypt_archive_name(&backup_name);
	let encrypted_archive = match backend.fetch_archive(&archive_id) {
		Ok(archive) => archive,
		Err(err) => {
			error!("There was a problem fetching the backup: {}", err);
			return;
		},
	};

	if debug_decrypt {
		let decrypted = match keystore.decrypt_archive_metadata(&archive_id, &encrypted_archive) {
			Ok(archive) => archive,
			Err(err) => {
				error!("There was a problem decrypting the backup: {}", err);
				return;
			}
		};
		io::stdout().write(&decrypted).expect("error while writing to stdout");
		return;
	}

	let archive = match Archive::decrypt(&archive_id, &encrypted_archive, &keystore) {
		Ok(archive) => archive,
		Err(err) => {
			error!("There was a problem decrypting the backup: {}", err);
			return;
		}
	};

	if archive.version != 0x00000001 {
		error!("Unsupported archive version");
		return;
	}

	let download_cache_dir = match tempfile::Builder::new().prefix("preserve-").tempdir() {
		Ok(dir) => dir,
		Err(err) => {
			error!("There was a problem creating a temporary directory: {}", err);
			return;
		},
	};
	let mut download_cache = HashMap::new();

	match build_block_refcounts(&archive.files, &mut download_cache) {
		Ok(x) => x,
		Err(err) => {
			error!("There was a problem reading the backup: {}", err);
			return;
		},
	}

	match extract_files(&config, &archive.files, target_directory, &keystore, download_cache_dir.path(), &mut download_cache, &mut *backend) {
		Ok(x) => x,
		Err(err) => {
			error!("There was a problem extracting the backup: {}", err);
			return;
		},
	}

	info!("Restore completed successfully");
}


#[derive(Default)]
struct Config {
	/// If true, hardlinks will be removed by cloning the file at all places it is referenced.
	/// If false, hardlinks are preserved.
	pub dereference_hardlinks: bool,
}


fn build_block_refcounts(files: &[File], download_cache: &mut HashMap<BlockId, DownloadCache>) -> Result<()> {
	for file in files {
		build_block_refcounts_helper(file, download_cache)?;
	}

	Ok(())
}


fn build_block_refcounts_helper(file: &File, download_cache: &mut HashMap<BlockId, DownloadCache>) -> Result<()> {
	for block_id in &file.blocks {
		download_cache.entry(block_id.clone()).or_insert(DownloadCache{
			refcount: 0,
			downloaded: false,
			id: block_id.clone(),
		});
		download_cache.get_mut(block_id).expect("internal error").refcount += 1;
	}

	Ok(())
}


fn extract_files<P: AsRef<Path>>(config: &Config, files: &[File], base_path: P, keystore: &KeyStore, cache_dir: &Path, download_cache: &mut HashMap<BlockId, DownloadCache>, backend: &mut dyn Backend) -> Result<()> {
	let mut hardlink_map: HashMap<u64, PathBuf> = HashMap::new();
	// List of all directories and the mtimes they need set.
	// We set these after extracting all files, since extracting the files changes the mtime of
	// directories.
	let mut directory_times = Vec::new();

	for file in files {
		let filepath = base_path.as_ref().join(&file.path);

		if let Some(ref symlink_path) = file.symlink {
			use std::os::unix;
			info!("Creating symlink: {} {}", symlink_path, filepath.display());
			unix::fs::symlink(symlink_path, &filepath)?;
		} else if file.is_dir {
			info!("Creating directory: {}", filepath.display());
			// Create and then set permissions.  This is done in two steps because
			// mkdir is affected by the current process's umask, whereas chmod (set_permissions) is not.
			fs::create_dir(&filepath)?;
			fs::set_permissions(&filepath, fs::Permissions::from_mode(file.mode))?;
			directory_times.push((filepath.clone(), file.mtime, file.mtime_nsec));
		} else {
			let hardlinked = if let Some(hardlink_id) = file.hardlink_id {
				if config.dereference_hardlinks {
					false
				} else {
					match hardlink_map.get(&hardlink_id) {
						Some(existing_path) => {
							info!("Hardlinking '{}' to '{}'", existing_path.display(), filepath.display());
							fs::hard_link(existing_path, &filepath)?;
							true
						},
						None => false,
					}
				}
			} else {
				false
			};

			if !hardlinked {
				info!("Writing file: {}", filepath.display());
				// We set permissions after creating the file because `open` uses umask.
				extract_file(&filepath, file, keystore, cache_dir, download_cache, backend)?;
				fs::set_permissions(&filepath, fs::Permissions::from_mode(file.mode))?;

				if !config.dereference_hardlinks {
					if let Some(hardlink_id) = file.hardlink_id {
						hardlink_map.insert(hardlink_id, filepath.clone());
					}
				}
			}
		}

		set_file_time(&filepath, file.mtime, file.mtime_nsec)?;
	}

	// Set mtime for directories.
	// We go in reverse, so we hit child directories before their parents
	directory_times.reverse();

	for (ref dirpath, ref mtime, ref mtime_nsec) in directory_times {
		set_file_time(dirpath, *mtime, *mtime_nsec)?;
	}

	Ok(())
}


fn extract_file<P: AsRef<Path>>(path: P, f: &File, keystore: &KeyStore, cache_dir: &Path, download_cache: &mut HashMap<BlockId, DownloadCache>, backend: &mut dyn Backend) -> Result<()> {
	// Don't overwrite existing files
	let file = fs::OpenOptions::new().write(true).create_new(true).open(path.as_ref())?;
	let mut writer = BufWriter::new(&file);
	let mut total_written = 0;

	for block_id in &f.blocks {
		let plaintext = cache_fetch(block_id, keystore, cache_dir, download_cache, backend)?;

		writer.write_all(&plaintext)?;
		total_written += plaintext.len();
	}

	if total_written as u64 != f.size {
		error!("The final extracted size of '{}' did not match what was expected: {} != {}", path.as_ref().display(), total_written, f.size);
	}

	Ok(())
}


fn cache_fetch(block_id: &BlockId, keystore: &KeyStore, cache_dir: &Path, download_cache: &mut HashMap<BlockId, DownloadCache>, backend: &mut dyn Backend) -> Result<Vec<u8>> {
	let cache = download_cache.get_mut(block_id).expect("internal error");
	let path = cache_dir.join(cache.id.to_string());

	if cache.downloaded {
		let plaintext = {
			let mut file = fs::File::open(path.clone())?;
			let mut plaintext = vec![0u8; 0];
			file.read_to_end(&mut plaintext)?;
			plaintext
		};

		cache.refcount -= 1;

		if cache.refcount == 0 {
			fs::remove_file(path)?;
		}

		Ok(plaintext)
	} else {
		let encrypted_block = backend.fetch_block(&cache.id)?;
		let plaintext = keystore.decrypt_block(&cache.id, &encrypted_block)?;

		cache.refcount -=1;
		cache.downloaded = true;

		if cache.refcount > 0 {
			let mut file = fs::File::create(path)?;
			file.write_all(&plaintext)?;
		}

		Ok(plaintext)
	}
}


fn set_file_time(path: &Path, mtime: i64, mtime_nsec: i64) -> Result<()> {
	use std::ffi::CString;
	use std::os::unix::prelude::*;
	use libc::{time_t, timespec, utimensat, c_long, AT_FDCWD, AT_SYMLINK_NOFOLLOW};

	let times = [timespec {
		tv_sec: mtime as time_t,
		tv_nsec: mtime_nsec as c_long,
	},
	timespec {
		tv_sec: mtime as time_t,
		tv_nsec: mtime_nsec as c_long,
	}];
	let p = CString::new(path.as_os_str().as_bytes()).expect("internal error");

	unsafe {
		if utimensat(AT_FDCWD, p.as_ptr() as *const _, times.as_ptr(), AT_SYMLINK_NOFOLLOW) == 0 {
			Ok(())
		} else {
			Err(io::Error::last_os_error().into())
		}
	}
}
