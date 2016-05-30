use std::error::Error as StdError;
use std::io::Error as IoError;
use rustc_serialize::json::DecoderError as JsonDecoderError;
use std::fmt;
use self::Error::*;

pub type Result<T> = ::std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
	/// I/O error
	Io(IoError),
	/// Error from JSON decoder
	JsonDecoder(JsonDecoderError),
	/// Bad Backend Path
	BadBackendPath(String),
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_str(self.description())
	}
}

impl StdError for Error {
	fn description(&self) -> &str {
		match *self {
			Io(ref e) => e.description(),
			JsonDecoder(_) => "Invalid JSON",
			BadBackendPath(ref e) => e,
		}
	}

	fn cause(&self) -> Option<&StdError> {
		match *self {
			Io(ref error) => Some(error),
			JsonDecoder(ref error) => Some(error),
			BadBackendPath(_) => None,
		}
	}
}

impl From<IoError> for Error {
	fn from(err: IoError) -> Error {
		Io(err)
	}
}

impl From<JsonDecoderError> for Error {
	fn from(err: JsonDecoderError) -> Error {
		JsonDecoder(err)
	}
}
