use log;
use time;
use std::fs::File;
use std::io::Write;
use std::sync::Mutex;
use std::path::Path;


pub struct Logger {
	log_level: log::LevelFilter,
	log_file: Option<Mutex<File>>,
}

impl log::Log for Logger {
	fn enabled(&self, metadata: &log::Metadata) -> bool {
		metadata.level() <= self.log_level
	}

	fn log(&self, record: &log::Record) {
		if !self.enabled(record.metadata()) {
			return;
		}

		let level = match record.level() {
			log::Level::Error => "ERROR",
			log::Level::Warn => "WARNING",
			log::Level::Info => "INFO",
			log::Level::Debug => "DEBUG",
			log::Level::Trace => "TRACE",
		};

		let timestamp = time::strftime("%Y-%m-%d %H:%M:%S", &time::now()).unwrap();

		// Log to the file if one was set
		if let Some(ref f) = self.log_file {
			let mut m = f.lock().unwrap();
			write!(m, "[{}] {}: {}\n", timestamp, level, record.args()).unwrap();
		}

		// Log to stdout
		match record.level() {
			log::Level::Info => println!("{}", record.args()),
			_ => println!("{}: {}", level, record.args()),
		}
	}

	fn flush(&self) {
		let stdout = std::io::stdout();
		stdout.lock().flush().unwrap();

		if let Some(ref f) = self.log_file {
			f.lock().unwrap().flush().unwrap();
		}
	}
}

impl Logger {
	pub fn init<P: AsRef<Path>>(log_level: log::LevelFilter, log_file_path: Option<P>) {
		let log_file = log_file_path.map(|path| {
			let file = File::create(path.as_ref()).unwrap_or_else(|err| {
				panic!("ERROR: Unable to open log file at '{}' for writing: {}", path.as_ref().display(), err)
			});
			Mutex::new(file)
		});

		log::set_boxed_logger(Box::new(Logger {
			log_level,
			log_file,
		})).unwrap_or_else(|err| {
			panic!("ERROR: Unable to initialize logger: {}", err)
		});
		log::set_max_level(log_level);
	}
}
