use mime::Mime;
use hyper::{self, header};
use hyper::method::Method;
use hyper::client::request::Request;
use hyper::http::Protocol;
use multipart::client::Multipart;
use url::{Url, form_urlencoded};
use url::ParseError as UrlError;
use std::io::{Cursor, Write};
use std::borrow::Borrow;
use std::time::Duration;


#[derive(Clone)]
pub struct RestBuilder {
	method: hyper::method::Method,
	url: Url,
	access_token: Option<String>,
	body: Option<Vec<u8>>,
	multiparts: Vec<RestBuilderMultipartPart>,
	content_type: Option<Mime>,
}

#[derive(Clone)]
struct RestBuilderMultipartPart {
	name: String,
	data: Vec<u8>,
	filename: Option<String>,
	content_type: Option<Mime>,
}


impl RestBuilder {
	pub fn get(url: &str) -> RestBuilder {
		RestBuilder::new(hyper::method::Method::Get, url)
	}

	pub fn post(url: &str) -> RestBuilder {
		RestBuilder::new(hyper::method::Method::Post, url)
	}

	pub fn new(method: hyper::method::Method, url: &str) -> RestBuilder {
		RestBuilder {
			method: method,
			url: Url::parse(url).unwrap(),
			access_token: None,
			body: None,
			multiparts: Vec::new(),
			content_type: None,
		}
	}

	pub fn url_push(mut self, piece: &str) -> RestBuilder {
		self.url.path_mut().unwrap().push(piece.to_owned());
		self
	}

	pub fn url_query<I, K, V>(mut self, query_pairs: I) -> RestBuilder where
		I: IntoIterator,
		I::Item: Borrow<(K, V)>,
		K: AsRef<str>,
		V: AsRef<str>
	{
		self.url.query = Some(form_urlencoded::serialize(query_pairs));
		self
	}

	pub fn authorization(mut self, access_token: &str) -> RestBuilder {
		self.access_token = Some(access_token.to_owned());
		self
	}

	pub fn body(mut self, body: &[u8]) -> RestBuilder {
		self.body = Some(body.to_vec());
		self
	}

	pub fn body_query<I, K, V>(mut self, query_pairs: I) -> RestBuilder where
		I: IntoIterator,
		I::Item: Borrow<(K, V)>,
		K: AsRef<str>,
		V: AsRef<str>
	{
		self.body = Some(form_urlencoded::serialize(query_pairs).as_bytes().to_vec());
		self.content_type = Some("application/x-www-form-urlencoded".parse().unwrap());
		self
	}

	pub fn multipart_urlencoded<I, K, V>(self, name: &str, query_pairs: I) -> RestBuilder where
		I: IntoIterator,
		I::Item: Borrow<(K, V)>,
		K: AsRef<str>,
		V: AsRef<str>
	{
		self.multipart_data(name, form_urlencoded::serialize(query_pairs).as_bytes(), None, None)
	}

	pub fn multipart_data(mut self, name: &str, data: &[u8], filename: Option<String>, content_type: Option<Mime>) -> RestBuilder {
		self.multiparts.push(RestBuilderMultipartPart {
			name: name.to_owned(),
			data: data.to_vec(),
			filename: filename,
			content_type: content_type,
		});
		self
	}

	pub fn send(self, protocol: &Box<Protocol>) -> hyper::error::Result<hyper::client::response::Response> {
		let message = {
			let (host, port) = try!(get_host_and_port(&self.url));
			try!(protocol.new_message(&host, port, &*self.url.scheme))
		};

		//let mut request = try!(Request::new(self.method, self.url));
		let mut request = try!(Request::with_message(self.method, self.url, message));

		try!(request.set_write_timeout(Some(Duration::from_secs(30))));
		try!(request.set_read_timeout(Some(Duration::from_secs(30))));

		if let Some(content_type) = self.content_type {
			request.headers_mut().set(header::ContentType(content_type))
		};

		if let Some(access_token) = self.access_token {
			request.headers_mut().set(header::Authorization(header::Bearer{token: access_token}));
		};

		if self.multiparts.len() > 0 {
			let mut multipart = try!(Multipart::from_request(request));

			for part in self.multiparts {
				let mut cursor = Cursor::new(part.data);
				match part.filename {
					Some(s) => multipart.write_stream(part.name, &mut cursor, Some(&s[..]), part.content_type),
					None => multipart.write_stream(part.name, &mut cursor, None, part.content_type),
				};
			}
			multipart.send()
		} else {
			match self.body {
				Some(ref body) => request.headers_mut().set(header::ContentLength(body.len() as u64)),
				None => request.headers_mut().set(header::ContentLength(0)),
			}
			let mut streaming = try!(request.start());
			if let Some(body) = self.body {
				try!(streaming.write_all(&body));
			}
			streaming.send()
		}
	}
}


fn get_host_and_port(url: &Url) -> hyper::error::Result<(String, u16)> {
	let host = match url.serialize_host() {
        Some(host) => host,
        None => return Err(hyper::error::Error::Uri(UrlError::EmptyHost))
    };
    let port = match url.port_or_default() {
        Some(port) => port,
        None => return Err(hyper::error::Error::Uri(UrlError::InvalidPort))
    };
    Ok((host, port))
}
