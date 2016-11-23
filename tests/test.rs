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
            Err(err) => {
                handle_failed_restore(original_dir.path(),
                                      restore_dir.path(),
                                      "Restored directory did not match original directory",
                                      &err)
            }
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
            Err(err) => {
                handle_failed_restore(original_dir.path(),
                                      restore_dir.path(),
                                      "Restored directory did not match original directory with \
                                       added file",
                                      &err)
            }
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
            Err(err) => {
                handle_failed_restore(original_dir.path(),
                                      restore_dir.path(),
                                      "Restored directory did not match original directory with \
                                       modified file",
                                      &err)
            }
        };
    }

    // Check old backup
    let original_dir = TestGenerator::new().generate_test_case();

    {
        let restore_dir = test_config.restore("test1");
        match compare_dirs(original_dir.path(), restore_dir.path()) {
            Ok(_) => (),
            Err(err) => {
                handle_failed_restore(original_dir.path(),
                                      restore_dir.path(),
                                      "Restored directory did not match old original directory",
                                      &err)
            }
        };
    }

    // Inverse test to make sure things are working as expected
    {
        let restore_dir = test_config.restore("test2");
        match compare_dirs(original_dir.path(), restore_dir.path()) {
            Ok(_) => {
                handle_failed_restore(original_dir.path(),
                                      restore_dir.path(),
                                      "Restored test2 should not match old original directory",
                                      "")
            }
            Err(_) => (),
        };
    }
}


// Dump our testcase to a folder so we can inspect it
#[test]
#[ignore]
fn dump_test_case() {
    // Test case
    let original_dir = TestGenerator::new().generate_test_case();

    // Save the test case
    let random_str: String = rand::thread_rng().gen_ascii_chars().take(10).collect();
    let path = Path::new("/tmp").join("preserve-testcase-".to_string() + &random_str);
    fs::rename(original_dir.path(), path).unwrap();
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
            .arg("--keyfile")
            .arg("keyfile")
            .output()
            .unwrap();
    }

    pub fn create<P: AsRef<Path>>(&self, backup_name: &str, path: P) {
        let output = Command::new(&self.bin)
            .current_dir(&self.working_dir)
            .arg("create")
            .arg("--keyfile")
            .arg("keyfile")
            .arg("--backend")
            .arg("file://".to_string() + &self.backend_dir.to_string_lossy())
            .arg(backup_name)
            .arg(path.as_ref())
            .output()
            .unwrap();

        println!("create-stdout: {}", String::from_utf8_lossy(&output.stdout));
        println!("create-stderr: {}", String::from_utf8_lossy(&output.stderr));
    }

    pub fn restore(&self, backup_name: &str) -> TempDir {
        let restore_dir = TempDir::new("preserve-test").unwrap();

        let output = Command::new(&self.bin)
            .current_dir(&self.working_dir)
            .arg("restore")
            .arg("--keyfile")
            .arg("keyfile")
            .arg("--backend")
            .arg("file://".to_string() + &self.backend_dir.to_string_lossy())
            .arg(backup_name)
            .arg(restore_dir.path())
            .output()
            .unwrap();

        println!("restore-stdout: {}",
                 String::from_utf8_lossy(&output.stdout));
        println!("restore-stderr: {}",
                 String::from_utf8_lossy(&output.stderr));

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

    // Create a temporary folder, fill it with our testcase, and return it.
    // The testcase is generated randomly; random file tree with random names, contents,
    // lengths, permissions, etc.
    // There is, however, some minimum requirements.  There will always be at least one empty
    // file, some symlinks, and some hardlinks.
    // Generation is deterministic.
    // The generation is performed by filling a folder with a random number of files, folders,
    // symlinks, and hardlinks.
    // Each generated folder is then recursively filled the same way.
    // TODO: Add requiment for bad symlinks
    fn generate_test_case(&mut self) -> TempDir {
        let basepath = TempDir::new("preserve-test").unwrap();
        let mut number_of_symlinks = 0;
        let mut number_of_hardlinks = 0;
        let mut number_of_empty_files = 0;
        let mut all_files = Vec::new();
        let mut all_folders = Vec::new();
        let mut tasks = Vec::new();

        tasks.push(basepath.path().to_path_buf());

        while let Some(parent) = tasks.pop() {
            // Prevent generating too deep
            let num_nodes_to_generate =
                if parent.strip_prefix(basepath.path()).unwrap().components().count() >= 3 {
                    0
                } else {
                    self.rng.gen_range(0, 18)
                };

            for _ in 0..num_nodes_to_generate {
                let filename = self.generate_random_name();
                let path = parent.join(filename);

                match self.rng.next_f32() {
                    // File
                    0.0...0.5 => {
                        self.generate_random_file(&path);

                        if path.metadata().unwrap().len() == 0 {
                            number_of_empty_files += 1;
                        }

                        all_files.push(path);
                    }
                    // Folder
                    0.5...0.8 => {
                        self.generate_random_folder(&path);
                        all_folders.push(path.clone());
                        tasks.push(path.clone());
                    }
                    // Symlink
                    0.8...0.9 => {
                        self.generate_random_symlink(&path, &all_files, &all_folders);
                        number_of_symlinks += 1;
                    }
                    // Hardlink
                    _ => {
                        if self.generate_random_hardlink(&path, &all_files) {
                            number_of_hardlinks += 1;
                        }
                    }
                };
            }

            // If our minimum requirements for the test case have not been met, then try again.
            if tasks.is_empty() &&
               (number_of_symlinks < 3 || number_of_hardlinks < 3 || number_of_empty_files < 1 ||
                all_folders.is_empty()) {
                tasks.push(basepath.path().to_path_buf());
            }
        }

        // Set random times for all the folders
        // We do this after, because generating the contents of the folders will undo what we set.
        // We do this in reverse, so that we set the children times before the parent folder.
        all_folders.reverse();

        for folder in all_folders {
            self.set_random_filetime(folder);
        }

        basepath
    }

    // Generate a random file name
    // Random length.  Randomly includes unicode.
    fn generate_random_name(&mut self) -> String {
        let alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.";
        let alphabet: Vec<char> = alphabet.chars().collect();
        let mut name = String::new();
        let mut name_tmp = String::new();
        let len = self.rng.gen_range(1, 256);

        loop {
            // 12% chance of being random alphanumeric unicode char, otherwise use alphabet above
            let c: char = if self.rng.next_u32() < 0x2000_0000 {
                self.rng.gen_iter::<char>().filter(|c| c.is_alphanumeric()).take(1).next().unwrap()
            } else {
                *self.rng.choose(&alphabet).unwrap()
            };

            name_tmp.push(c);

            if name_tmp.len() > len {
                return name;
            }

            name.push(c);
        }
    }

    // Generate a random file at the given path.
    // Length, contents, permissions, etc. will be random.
    fn generate_random_file<P: AsRef<Path>>(&mut self, path: P) {
        let mode = (self.rng.next_u32() & 511) | 0o600;
        let len = match self.rng.next_f32() {
            0.0...0.1 => 0, // Empty (10%)
            0.1...0.6 => self.rng.gen_range(1, 1024), // Small
            0.6...0.9 => self.rng.gen_range(1, 2 * 1024 * 1024), // Medium
            _ => self.rng.gen_range(1, 32 * 1024 * 1024), // Large
        };

        {
            let file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .mode(mode)
                .open(path.as_ref())
                .unwrap();
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

    fn generate_random_folder<P: AsRef<Path>>(&mut self, path: P) {
        let mode = (self.rng.next_u32() & 511) | 0o700;
        fs::DirBuilder::new().mode(mode).create(path).unwrap();
    }

    // Generate a symlink at the given path, linking randomly to one of the potential_folders
    // or potential_files.
    // The link's path to the target will be relative.
    // If no targets are possible, or randomly, a bad symlink will be generated
    fn generate_random_symlink<P: AsRef<Path>>(&mut self,
                                               path: P,
                                               potential_files: &[PathBuf],
                                               potential_folders: &[PathBuf]) {
        let target = if self.rng.gen() {
            if self.rng.gen() {
                None // Bad symlink
            } else {
                self.rng.choose(potential_files)
            }
        } else {
            self.rng.choose(potential_folders)
        };

        let target = match target {
            Some(target) => {
                TestGenerator::calculate_relative_path(path.as_ref().parent().unwrap(), target)
            }
            None => PathBuf::from(self.generate_random_name()),  // Bad symlink
        };

        unix::fs::symlink(target, path.as_ref()).unwrap();
        self.set_random_filetime(path.as_ref());
    }

    // Returns a path relative to from (must be a directory) which gets to to
    // (either directory or file)
    fn calculate_relative_path<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> PathBuf {
        let mut result = String::new();
        let mut current = from.as_ref().to_path_buf();

        loop {
            match to.as_ref().strip_prefix(&current) {
                Ok(remaining) => {
                    let final_result = PathBuf::from(result).join(remaining);

                    return if final_result.to_string_lossy() == "" {
                        PathBuf::from("./")
                    } else {
                        final_result
                    };
                }
                Err(_) => (),
            }

            result.push_str("../");
            current.pop();
        }
    }

    // Generate a hardlink at the given path, linking randomly to one of the potential_files.
    // Returns false when potential_files is empty
    fn generate_random_hardlink<P: AsRef<Path>>(&mut self,
                                                path: P,
                                                potential_files: &[PathBuf])
                                                -> bool {
        match self.rng.choose(potential_files) {
            Some(target) => {
                fs::hard_link(target, path).unwrap();
                true
            }
            None => false,
        }
    }

    fn generate_random_filetime(&mut self) -> (i64, i64) {
        let base_time = 1456713592;

        (self.rng.gen_range(base_time - 256000, base_time + 256000),
         self.rng.gen_range(0, 1000000000))
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
                if utimensat(AT_FDCWD,
                             p.as_ptr() as *const _,
                             times.as_ptr(),
                             AT_SYMLINK_NOFOLLOW) == 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            }
            .unwrap();
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
fn handle_failed_restore<P: AsRef<Path>, Q: AsRef<Path>>(original_dir: P,
                                                         restore_dir: Q,
                                                         reason: &str,
                                                         err: &str) {
    let mut rng = rand::thread_rng();
    let random_str: String = rng.gen_ascii_chars().take(10).collect();

    fs::rename(original_dir,
               "/tmp/preserve-test-failed-original-".to_string() + &random_str)
        .unwrap();
    fs::rename(restore_dir,
               "/tmp/preserve-test-failed-restore-".to_string() + &random_str)
        .unwrap();
    panic!("{}\nOriginal and Restore directories have been saved for inspection: \
            /tmp/preserve-test-failed-*-{}\nrsync output:\n{}",
           reason,
           random_str,
           err)
}
