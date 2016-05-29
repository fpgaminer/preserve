use log::{self, LogRecord, LogLevel, LogLevelFilter, LogMetadata, SetLoggerError};
use time;
use std::fs::File;
use std::io::Write;
use std::sync::Mutex;
use std::path::Path;


pub struct Logger {
	log_level: LogLevelFilter,
	log_file: Option<Mutex<File>>,
}

impl log::Log for Logger {
	fn enabled(&self, metadata: &LogMetadata) -> bool {
		metadata.level() <= self.log_level
	}

	fn log(&self, record: &LogRecord) {
		if !self.enabled(record.metadata()) {
			return;
		}

		let level = match record.level() {
			LogLevel::Error => "ERROR",
			LogLevel::Warn => "WARNING",
			LogLevel::Info => "INFO",
			LogLevel::Debug => "DEBUG",
			LogLevel::Trace => "TRACE",
		};

		let timestamp = time::strftime("%Y-%m-%d %H:%M:%S", &time::now()).unwrap();

		if let Some(ref f) = self.log_file {
			let mut m = f.lock().unwrap();
			write!(m, "[{}] {}: {}\n", timestamp, level, record.args()).unwrap();
		}

		match record.level() {
			LogLevel::Info => println!("{}", record.args()),
			_ => println!("{}: {}", level, record.args()),
		}
	}
}

impl Logger {
	pub fn init<P: AsRef<Path>>(log_level: LogLevelFilter, log_file_path: Option<P>) -> Result<(), SetLoggerError> {
		let log_file = log_file_path.map(|path| Mutex::new(File::create(path).unwrap()));

		log::set_logger(|max_log_level| {
			max_log_level.set(log_level);
			Box::new(Logger {
				log_level: log_level,
				log_file: log_file,
			})
		})
	}
}
