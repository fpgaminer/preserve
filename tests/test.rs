extern crate tempdir;
extern crate rand;
extern crate libc;

use std::process::Command;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::io::{Write, BufWriter};
use tempdir::TempDir;
use rand::{Rng, ChaChaRng};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, MetadataExt};
use std::cmp;
use std::os::unix;


#[test]
fn integration_test_1() {
	let working_dir = TempDir::new("preserve-test").unwrap();
	let backend_dir = TempDir::new("preserve-test").unwrap();

	let test_config = TestConfig {
		bin: Path::new("target/debug/preserve").canonicalize().unwrap(),
		working_dir: working_dir.path().to_path_buf(),
		backend_dir: backend_dir.path().to_path_buf(),
	};

	// Generate keyfile
	test_config.init();

	// Test case
	let original_dir = TestGenerator::new().generate_test_case();

	// First test
	{
		test_config.create("test1", original_dir.path());
		let restore_dir = test_config.restore("test1");
		match compare_dirs(original_dir.path(), restore_dir.path()) {
			Ok(_) => (),
			Err(err) => handle_failed_restore(original_dir.path(), restore_dir.path(), "Restored directory did not match original directory", &err),
		};
	}

	// Add a file
	{
		let mut file = File::create(original_dir.path().join("test.txt")).unwrap();
		file.write_all(b"This is a new file").unwrap();
	}

	// Test again
	{
		test_config.create("test2", original_dir.path());
		let restore_dir = test_config.restore("test2");
		match compare_dirs(original_dir.path(), restore_dir.path()) {
			Ok(_) => (),
			Err(err) => handle_failed_restore(original_dir.path(), restore_dir.path(), "Restored directory did not match original directory with added file", &err),
		};
	}

	// Modify a file
	{
		let mut file = File::create(original_dir.path().join("test.txt")).unwrap();
		file.write_all(b"This is a different file").unwrap();
	}

	// Test again
	{
		test_config.create("test3", original_dir.path());
		let restore_dir = test_config.restore("test3");
		match compare_dirs(original_dir.path(), restore_dir.path()) {
			Ok(_) => (),
			Err(err) => handle_failed_restore(original_dir.path(), restore_dir.path(), "Restored directory did not match original directory with modified file", &err),
		};
	}

	// Check old backup
	let original_dir = TestGenerator::new().generate_test_case();

	{
		let restore_dir = test_config.restore("test1");
		match compare_dirs(original_dir.path(), restore_dir.path()) {
			Ok(_) => (),
			Err(err) => handle_failed_restore(original_dir.path(), restore_dir.path(), "Restored directory did not match old original directory", &err),
		};
	}

	// Inverse test to make sure things are working as expected
	{
		let restore_dir = test_config.restore("test2");
		match compare_dirs(original_dir.path(), restore_dir.path()) {
			Ok(_) => handle_failed_restore(original_dir.path(), restore_dir.path(), "Restored test2 should not match old original directory", ""),
			Err(_) => (),
		};
	}
}


// Information about the current test, such as the temporary directories where we're storing
// the keyfile, backend path, etc.
struct TestConfig {
	pub bin: PathBuf,
	pub working_dir: PathBuf,
	pub backend_dir: PathBuf,
}

impl TestConfig {
	pub fn init(&self) {
		Command::new(&self.bin)
			.current_dir(&self.working_dir)
			.arg("keygen")
			.arg("--keyfile").arg("keyfile")
			.output().unwrap();
	}

	pub fn create<P: AsRef<Path>>(&self, backup_name: &str, path: P) {
		let output = Command::new(&self.bin)
			.current_dir(&self.working_dir)
			.arg("create")
			.arg("--keyfile").arg("keyfile")
			.arg("--backend").arg("file")
			.arg("--backend-path").arg(&self.backend_dir)
			.arg(backup_name)
			.arg(path.as_ref())
			.output().unwrap();

		println!("create-stdout: {}", String::from_utf8_lossy(&output.stdout));
		println!("create-stderr: {}", String::from_utf8_lossy(&output.stderr));
	}

	pub fn restore(&self, backup_name: &str) -> TempDir {
		let restore_dir = TempDir::new("preserve-test").unwrap();

		let output = Command::new(&self.bin)
			.current_dir(&self.working_dir)
			.arg("restore")
			.arg("--keyfile").arg("keyfile")
			.arg("--backend").arg("file")
			.arg("--backend-path").arg(&self.backend_dir)
			.arg(backup_name)
			.arg(restore_dir.path())
			.output().unwrap();

		println!("restore-stdout: {}", String::from_utf8_lossy(&output.stdout));
		println!("restore-stderr: {}", String::from_utf8_lossy(&output.stderr));

		restore_dir
	}
}


struct TestGenerator {
	rng: Box<Rng>,
}


impl TestGenerator {
	fn new() -> TestGenerator {
		TestGenerator {
			// Deterministic seed
			rng: Box::new(ChaChaRng::new_unseeded()),
		}
	}

	// Generate a file at the given path with random binary data of the given length.
	// The file's permissions will be random, but OR'd with mode_or so you can force certain permissions.
	// The file mtime will be a random variation on base_time.
	fn generate_random_file<P: AsRef<Path>>(&mut self, path: P, len: usize) {
		let mode = (self.rng.next_u32() & 511) | 0o400;
		{
			let file = fs::OpenOptions::new().write(true).create(true).mode(mode).open(path.as_ref()).unwrap();
			let mut writer = BufWriter::new(file);
			let mut written = 0;
			let mut buffer = [0u8; 4096];

			while written < len {
				let chunk_size = cmp::min(buffer.len(), len - written);

				self.rng.fill_bytes(&mut buffer);
				writer.write_all(&buffer[..chunk_size]).unwrap();
				written += chunk_size;
			}
		}

		self.set_random_filetime(path);
	}

	// Fill destination folder with our test case, which we will backup, restore, modify, etc for the various tests.
	fn generate_test_case(&mut self) -> TempDir {
		let path = TempDir::new("preserve-test").unwrap();

		let len = self.rng.gen_range(1, 4*1024*1024);
		self.generate_random_file(path.path().join("foo.bin"), len);
		let len = self.rng.gen_range(1, 4*1024*1024);
		self.generate_random_file(path.path().join("foo2.bin"), len);
		let len = self.rng.gen_range(1, 1*1024*1024);
		self.generate_random_file(path.path().join("testfile.txt"), len);
		let len = self.rng.gen_range(1, 1*1024*1024);
		self.generate_random_file(path.path().join("testfile2.txt"), len);
		self.generate_random_file(path.path().join("EMPTY"), 0);

		fs::DirBuilder::new().mode(self.rng.gen_range(0, 512) | 0o700).create(path.path().join("testfolder")).unwrap();
		let len = self.rng.gen_range(1, 4*1024*1024);
		self.generate_random_file(path.path().join("testfolder").join("foo.bin"), len);
		let len = self.rng.gen_range(1, 1*1024*1024);
		self.generate_random_file(path.path().join("testfolder").join("preserve_me"), len);

		fs::DirBuilder::new().mode(self.rng.gen_range(0, 512) | 0o700).create(path.path().join("otherfolder")).unwrap();
		let len = self.rng.gen_range(1, 4*1024*1024);
		self.generate_random_file(path.path().join("otherfolder").join("hello.world"), len);
		let len = self.rng.gen_range(1, 1*1024*1024);
		self.generate_random_file(path.path().join("otherfolder").join("( ͡° ͜ʖ ͡°)"), len);
		fs::DirBuilder::new().mode(self.rng.gen_range(0, 512) | 0o700).create(path.path().join("otherfolder").join("subfolder")).unwrap();
		let len = self.rng.gen_range(1, 4*1024*1024);
		self.generate_random_file(path.path().join("otherfolder").join("subfolder").join("box_of_kittens"), len);

		unix::fs::symlink("testfolder", path.path().join("symfolder")).unwrap();
		self.set_random_filetime(path.path().join("symfolder"));

		unix::fs::symlink("testfile.txt", path.path().join("symfile")).unwrap();
		self.set_random_filetime(path.path().join("symfile"));

		unix::fs::symlink("otherfolder/box_of_kittens", path.path().join("testfolder").join("badsym")).unwrap();
		self.set_random_filetime(path.path().join("testfolder").join("badsym"));

		unix::fs::symlink("../otherfolder/subfolder/box_of_kittens", path.path().join("testfolder").join("symfile")).unwrap();
		self.set_random_filetime(path.path().join("testfolder").join("symfile"));

		fs::hard_link(path.path().join("testfolder").join("foo.bin"), path.path().join("otherfolder").join("hardfile")).unwrap();
		fs::hard_link(path.path().join("otherfolder").join("hello.world"), path.path().join("testfolder").join("hardfile")).unwrap();

		// Set time for directories
		self.set_random_filetime(path.path().join("otherfolder").join("subfolder"));
		self.set_random_filetime(path.path().join("otherfolder"));
		self.set_random_filetime(path.path().join("testfolder"));

		path
	}

	fn generate_random_filetime(&mut self) -> (i64, i64) {
		let base_time = 1456713592;

		(self.rng.gen_range(base_time-256000, base_time+256000), self.rng.gen_range(0, 1000000000))
	}

	fn set_random_filetime<P: AsRef<Path>>(&mut self, path: P) {
		let (time, time_nsec) = self.generate_random_filetime();

		TestGenerator::set_file_time(path, time, time_nsec);
	}

	// Does not follow symlinks, so if used on a symlink it will set the mtime
	// for the link itself, rather than the file the link points to.
	fn set_file_time<P: AsRef<Path>>(path: P, mtime: i64, mtime_nsec: i64) {
		use std::ffi::CString;
		use std::os::unix::prelude::*;
		use libc::{time_t, timespec, utimensat, c_long, AT_FDCWD, AT_SYMLINK_NOFOLLOW};
		use std::io;

		let times = [timespec {
			tv_sec: mtime as time_t,
			tv_nsec: mtime_nsec as c_long,
		},
		timespec {
			tv_sec: mtime as time_t,
			tv_nsec: mtime_nsec as c_long,
		}];
		let p = CString::new(path.as_ref().as_os_str().as_bytes()).unwrap();

		unsafe {
			if utimensat(AT_FDCWD, p.as_ptr() as *const _, times.as_ptr(), AT_SYMLINK_NOFOLLOW) == 0 {
				Ok(())
			} else {
				Err(io::Error::last_os_error())
			}
		}.unwrap();
	}
}

// Compares the given directories using rsync.
// The returned error String is the output of rsync when they don't match.
fn compare_dirs<P: AsRef<Path>, Q: AsRef<Path>>(path1: P, path2: Q) -> Result<(), String> {
	// rsync should compare mtime, permissions, contents, etc.
	let output = Command::new("rsync")
		.arg("-avnci")     // Archive mode, verbose, dry-run, checksum, itemized list
		.arg("--delete")  // Check for missing files
		.arg(path1.as_ref().to_str().unwrap().to_string() + "/")
		.arg(path2.as_ref().to_str().unwrap().to_string() + "/")
		.output().unwrap();

	let output = String::from_utf8_lossy(&output.stdout);
	let mut output_lines = output.lines();

	let mut same = true;

	same &= output_lines.next().unwrap_or("x") == "sending incremental file list";
	same &= match output_lines.next().unwrap_or("x") {
		".d..t...... ./" => output_lines.next().unwrap_or("x") == "",
		"" => true,
		_ => false,
	};
	same &= output_lines.next().unwrap_or("x").starts_with("sent ");
	same &= output_lines.next().unwrap_or("x").starts_with("total ");

	if same {
		Ok(())
	} else {
		Err(output.to_string())
	}
}

// We use temporary directories for everything, so in the case of failure save the directories
// for inspection, and then panic with the error message.
fn handle_failed_restore<P: AsRef<Path>, Q: AsRef<Path>>(original_dir: P, restore_dir: Q, reason: &str, err: &str) {
	let mut rng = rand::thread_rng();
	let random_str: String = rng.gen_ascii_chars().take(10).collect();

	fs::rename(original_dir, "/tmp/preserve-test-failed-original-".to_string() + &random_str).unwrap();
	fs::rename(restore_dir, "/tmp/preserve-test-failed-restore-".to_string() + &random_str).unwrap();
	panic!("{}\nOriginal and Restore directories have been saved for inspection: /tmp/preserve-test-failed-*-{}\nrsync output:\n{}", reason, random_str, err)
}
