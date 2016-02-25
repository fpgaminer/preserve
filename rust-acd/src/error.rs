use std::error::Error as StdError;
use hyper::error::Error as HyperError;
use std::io::Error as IoError;
use rustc_serialize::json::DecoderError as JsonError;
use std::fmt;


use self::Error::*;

pub type Result<T> = ::std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
	/// Error from Hyper (HTTP client)
	Hyper(HyperError),
	/// I/O error
	Io(IoError),
	/// Invalid path.  The path specified could not be parsed.
	BadPath,
	/// Server response was expected to be a string, but we couldn't decode it as UTF-8
	ResponseNotUtf8(Vec<u8>),
	/// Server response was supposed to be JSON, but we couldn't decode as expected
	ResponseBadJson(JsonError),
	/// Server's response was not as expected, probably an error
	UnknownServerError(String),
	/// Node (file/directory) exists
	NodeExists,
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_str(self.description())
	}
}

impl StdError for Error {
	fn description(&self) -> &str {
		match *self {
			Hyper(ref e) => e.description(),
			Io(ref e) => e.description(),
			BadPath => "Invalid path provided",
			ResponseNotUtf8(_) => "Server response was supposed to be UTF-8, but wasn't",
			ResponseBadJson(ref e) => e.description(),
			UnknownServerError(ref e) => e,
			NodeExists => "Node exists",
		}
	}

	fn cause(&self) -> Option<&StdError> {
		match *self {
			Hyper(ref error) => Some(error),
			Io(ref error) => Some(error),
			BadPath => None,
			ResponseNotUtf8(_) => None,
			ResponseBadJson(ref error) => Some(error),
			UnknownServerError(_) => None,
			NodeExists => None,
		}
	}
}

impl From<HyperError> for Error {
	fn from(err: HyperError) -> Error {
		Hyper(err)
	}
}

impl From<IoError> for Error {
	fn from(err: IoError) -> Error {
		Io(err)
	}
}
