use log::{self, LogRecord, LogLevel, LogLevelFilter, LogMetadata, SetLoggerError};
use time;
use std::fs::File;
use std::io::Write;
use std::sync::Mutex;


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
	pub fn init(log_level: LogLevelFilter) -> Result<(), SetLoggerError> {
		let f = File::create("log.txt").unwrap();

		log::set_logger(|max_log_level| {
			max_log_level.set(log_level);
			Box::new(Logger {
				log_level: log_level,
				log_file: Some(Mutex::new(f)),
			})
		})
	}
}
