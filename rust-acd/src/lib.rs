extern crate hyper;
extern crate multipart;
extern crate url;
#[macro_use]
extern crate mime;
extern crate rustc_serialize;
extern crate time;
extern crate crypto;
extern crate rusqlite;

pub mod rest;
pub mod error;

use url::{Url, form_urlencoded};
use std::process::Command;
use std::io::{self, Read, Write};
use rustc_serialize::{json, Decodable, Encodable};
use rustc_serialize::hex::ToHex;
use std::fs::File;
use time::Timespec;
use std::path::{Path, Component};
use rest::RestBuilder;
use error::{Result, Error};
use std::time::Duration;
use hyper::status::StatusCode;
use crypto::md5::Md5;
use crypto::digest::Digest;
use rusqlite::Connection;
use hyper::http;
use hyper::client::pool::Pool;


/// How many times we retry contacting Amazon after a server error
const DEFAULT_RETRY: u8 = 5;
/// How many hours to hold onto an endpoint (after which the endpoint is refreshed)
const REFRESH_ENDPOINT_TIME: i64 = 3*24;


#[derive(RustcEncodable, RustcDecodable)]
pub struct SecurityProfile {
	pub client_id: String,
	pub client_secret: String,
}

#[derive(RustcEncodable, RustcDecodable)]
pub struct Authorization {
	pub access_token: Option<String>,
	pub refresh_token: String,
	pub token_type: String,
	pub date_last_updated: i64,
}

#[derive(RustcEncodable, RustcDecodable)]
pub struct Endpoint {
	pub content_url: String,
	pub metadata_url: String,
	pub date_last_updated: i64,
}




#[derive(RustcDecodable, Debug)]
struct O2TokenResponse {
	pub access_token: String,
	pub refresh_token: String,
	pub token_type: String,
	pub expires_in: u64,
}

#[derive(RustcDecodable, Debug)]
#[allow(non_snake_case)]
struct AccountEndpointResponse {
	pub contentUrl: String,
	pub metadataUrl: String,
}

#[derive(RustcDecodable, Debug)]
struct NodeResponse {
	pub id: String,
}

#[derive(RustcDecodable, Debug)]
#[allow(non_snake_case)]
struct NodesResponse {
	pub count: u64,
	pub nextToken: Option<String>,
	pub data: Vec<NodeResponse>,
}

#[derive(RustcDecodable, Debug)]
struct NodeUploadResponseContentProperties {
	pub md5: String,
}

#[derive(RustcDecodable, Debug)]
#[allow(non_snake_case)]
struct NodeUploadResponse {
	pub id: String,
	pub contentProperties: NodeUploadResponseContentProperties,
}


pub struct AmazonCloudDrive {
	security_profile: SecurityProfile,
	authorization: Authorization,
	endpoint: Endpoint,
	root_id: String,
	cache_conn: Connection,
	protocol: Box<http::Protocol>,
}


impl AmazonCloudDrive {
	pub fn new() -> Result<AmazonCloudDrive> {
		let cache_conn = Connection::open("acd.cache.sqlite").unwrap();

		cache_conn.execute("CREATE TABLE IF NOT EXISTS path_cache (
			parent TEXT NOT NULL,
			name TEXT NOT NULL,
			id TEXT NOT NULL
		)", &[]).unwrap();

		cache_conn.execute("CREATE INDEX IF NOT EXISTS idx_path_cache_parent_name ON path_cache (parent, name);", &[]).unwrap();
		cache_conn.execute("CREATE INDEX IF NOT EXISTS idx_path_cache_parent ON path_cache (parent);", &[]).unwrap();

		let security_profile = read_json_file("acd.security_profile.json").unwrap();
		let endpoint = read_json_file("acd.endpoint.json").unwrap_or(Endpoint {
			content_url: "".to_owned(),
			metadata_url: "".to_owned(),
			date_last_updated: 0,
		});
		let authorization = read_json_file("acd.authorization.json").unwrap_or(Authorization {
			access_token: None,
			refresh_token: "".to_owned(),
			token_type: "".to_owned(),
			date_last_updated: 0,
		});

		let mut acd = AmazonCloudDrive {
			security_profile: security_profile,
			authorization: authorization,
			endpoint: endpoint,
			root_id: String::new(),
			cache_conn: cache_conn,
			protocol: Box::new(http::h1::Http11Protocol::with_connector(Pool::new(Default::default()))),
		};

		if let None = acd.authorization.access_token {
			try!(acd.authorize());
			write_json_file("acd.authorization.json", &acd.authorization);
		}

		try!(acd.refresh_endpoint());
		write_json_file("acd.endpoint.json", &acd.endpoint);
		acd.root_id = try!(acd.find_root());
		Ok(acd)
	}

	fn insert_into_node_cache(&mut self, parent: &str, name: &str, id: &str) {
		self.cache_conn.execute("INSERT INTO path_cache (parent, name, id) VALUES (?,?,?)", &[&parent.to_owned(), &name.to_owned(), &id.to_owned()]).unwrap();
	}

	fn fetch_from_node_cache(&self, parent: &str, name: &str) -> Option<String> {
		let result = self.cache_conn.query_row("SELECT id FROM path_cache WHERE parent=? AND name=?", &[&parent.to_owned(), &name.to_owned()], |row| {
        	row.get(0)
    	});

		match result {
			Ok(id) => Some(id),
			Err(rusqlite::Error::QueryReturnedNoRows) => None,
			Err(err) => panic!("Sqlite error: {}", err),
		}
	}

	pub fn get_server_response(&mut self, rest: RestBuilder, repeat: bool, retry: u8) -> Result<(hyper::status::StatusCode, Vec<u8>)> {
		#[derive(RustcDecodable, Debug)]
		struct MessageResponse {
			message: String,
		}

		let rest_copy = rest.clone();
		let mut response = match rest.send(&self.protocol) {
			Ok(r) => r,
			Err(err) => if retry > 0 {
				println!("INFO: Error during request: Retries left: {}", retry);
				std::thread::sleep(Duration::from_secs(5));
				return self.get_server_response(rest_copy, repeat, retry - 1);
			} else {
				return Err(error::Error::from(err))
			},
		};

		let mut body = vec![0u8; 0];
		match response.read_to_end(&mut body) {
			Ok(_) => (),
			Err(err) => if retry > 0 {
				println!("INFO: Error during request: Retries left: {}", retry);
				std::thread::sleep(Duration::from_secs(5));
				return self.get_server_response(rest_copy, repeat, retry - 1);
			} else {
				return Err(error::Error::from(err))
			},
		};

		if response.status.is_success() {
			return Ok((response.status, body));
		}

		// Errors usually have some JSON error message associated with them
		let body_string = String::from_utf8(body.clone());
		let body_json: Option<MessageResponse> = match body_string {
			Ok(s) => match json::decode(&s) {
				Ok(msg) => Some(msg),
				Err(_) => None,
			},
			Err(_) => None,
		};

		// The ACD API is supposed to return 401 when we need to reauth, but I found them returning
		// 400 Bad Request, with a JSON message saying the status code was 401 and that the token had expired.
		// ...Whut?
		// So don't analyze status code; just check for "Token has expired"
		let need_reauth = match body_json {
			Some(msg) => msg.message.contains("Token has expired"),
			_ => false,
		};

		if need_reauth && repeat {
			/* Kill the old token, so using it again panics */
			self.authorization.access_token = None;
			/* Re-authorize */
			try!(self.refresh_authorization());
			/* Try again */
			let rest_copy = rest_copy.authorization(&(self.authorization.access_token.clone().unwrap()));
			return self.get_server_response(rest_copy, false, retry);
		}

		// If we need to reauth, but we've tried that already, error out.
		if need_reauth {
			return Ok((response.status, body));
		}

		if retry > 0 {
			println!("INFO: Amazon returned status {:?}: Retries left: {}", response.status, retry);
			std::thread::sleep(Duration::from_secs(5));
			return self.get_server_response(rest_copy, repeat, retry - 1);
		}

		Ok((response.status, body))
	}

	fn refresh_endpoint(&mut self) -> Result<()> {
		let date_last_updated = Timespec::new(self.endpoint.date_last_updated, 0);
		let now = time::get_time();

		if (now - date_last_updated).num_hours() < REFRESH_ENDPOINT_TIME {
			return Ok(())
		}

		let request = RestBuilder::get("https://drive.amazonaws.com/drive/v1/account/endpoint")
			.authorization(&(self.authorization.access_token.clone().unwrap()));
		let (status_code, body) = try!(self.get_server_response(request, true, DEFAULT_RETRY));

		let response: AccountEndpointResponse = match status_code {
			StatusCode::Ok => {
				try!(decode_server_json(&body))
			},
			_ => return Err(Error::UnknownServerError(format!("Unknown Server Response, probably an error. Status was {}, Body was {:?}", status_code, String::from_utf8(body)))),
		};

		self.endpoint = Endpoint {
			content_url: response.contentUrl,
			metadata_url: response.metadataUrl,
			date_last_updated: time::get_time().sec,
		};

		Ok(())
	}

	fn authorize(&mut self) -> Result<()> {
		/* First, direct the user to the Amazon login page */
		open_webbrowser(&("https://www.amazon.com/ap/oa?".to_string() + &form_urlencoded::serialize(&[
			("client_id", &self.security_profile.client_id),
			("scope", &"clouddrive:read_all clouddrive:write".to_owned()),
			("response_type", &"code".to_owned()),
			("redirect_uri", &"http://localhost:26619/".to_owned())
		])));

		/* After they login, their browser will redirect to the authorization URL which contains the
		 * code we need.  The user should copy the URL from their browser and paste it into the console
		 */
		println!("Paste the response url:");
		let code = {
			let mut response_url = String::new();
			io::stdin().read_line(&mut response_url).unwrap();

			let response_pairs = Url::parse(&response_url).unwrap().query_pairs().unwrap();
			let code = response_pairs.iter().find(|&x| x.0 == "code").unwrap();
			&code.1.clone()
		};

		/* Get authorization tokens from Amazon using the code */
		let request = RestBuilder::post("https://api.amazon.com/auth/o2/token")
			.body_query(&[
				("grant_type", "authorization_code"),
				("code", code),
				("client_id", &self.security_profile.client_id),
				("client_secret", &self.security_profile.client_secret),
				("redirect_uri", "http://localhost:26619/")
			]);
		let (status_code, body) = try!(self.get_server_response(request, false, DEFAULT_RETRY));

		let response: O2TokenResponse = match status_code {
				StatusCode::Ok => {
					try!(decode_server_json(&body))
				},
				_ => return Err(Error::UnknownServerError(format!("Unknown Server Response, probably an error. Status was {}, Body was {:?}", status_code, String::from_utf8(body)))),
			};

		self.authorization = Authorization {
			access_token: Some(response.access_token),
			refresh_token: response.refresh_token,
			token_type: response.token_type,
			date_last_updated: time::get_time().sec,
		};

		Ok(())
	}

	fn refresh_authorization(&mut self) -> Result<()> {
		println!("Refreshing authorization");

		let request = RestBuilder::post("https://api.amazon.com/auth/o2/token")
			.body_query(&[
				("grant_type", "refresh_token"),
				("refresh_token", &self.authorization.refresh_token),
				("client_id", &self.security_profile.client_id),
				("client_secret", &self.security_profile.client_secret),
				("redirect_uri", "http://localhost:26619/")
			]);
		let (status_code, body) = try!(self.get_server_response(request, false, DEFAULT_RETRY));

		let response: O2TokenResponse = match status_code {
			StatusCode::Ok => {
				try!(decode_server_json(&body))
			},
			_ => return Err(Error::UnknownServerError(format!("Unknown Server Response, probably an error. Status was {}, Body was {:?}", status_code, String::from_utf8(body)))),
		};

		self.authorization = Authorization {
			access_token: Some(response.access_token),
			refresh_token: response.refresh_token,
			token_type: response.token_type,
			date_last_updated: time::get_time().sec,
		};

		write_json_file("acd.authorization.json", &self.authorization);

		Ok(())
	}

	fn find_root(&mut self) -> Result<String> {
		let request = RestBuilder::get(&self.endpoint.metadata_url.clone())
			.url_push("nodes")
			.url_query(&[("filters", "kind:FOLDER AND isRoot:true")])
			.authorization(&self.authorization.access_token.clone().unwrap());

		let (status_code, body) = try!(self.get_server_response(request, true, DEFAULT_RETRY));

		match status_code {
			StatusCode::Ok => {
				let response: NodesResponse = try!(decode_server_json(&body));
				Ok(response.data[0].id.clone())
			},
			_ => Err(Error::UnknownServerError(format!("Unknown Server Response, probably an error. Status was {}, Body was {:?}", status_code, String::from_utf8(body)))),
		}
	}

	pub fn find_child(&mut self, parent: &str, name: &str) -> Result<Option<String>> {
		if let Some(id) = self.fetch_from_node_cache(parent, name) {
			return Ok(Some(id));
		}

		let request = RestBuilder::get(&self.endpoint.metadata_url)
			.url_push("nodes")
			.url_push(parent)
			.url_push("children")
			.url_query(&[("filters", "name:".to_owned() + name)])
			.authorization(&self.authorization.access_token.clone().unwrap());
		let (status_code, body) = try!(self.get_server_response(request, true, DEFAULT_RETRY));

		match status_code {
			StatusCode::Ok => {
				let response: NodesResponse = try!(decode_server_json(&body));
				if response.data.len() == 0 {
					return Ok(None);
				}
				self.insert_into_node_cache(parent, name, &response.data[0].id);
				Ok(Some(response.data[0].id.clone()))
			},
			_ => return Err(Error::UnknownServerError(format!("Unknown Server Response, probably an error. Status was {}, Body was {:?}", status_code, String::from_utf8(body)))),
		}
	}

	pub fn find_path<P: AsRef<Path>>(&mut self, parent: Option<&str>, path: P) -> Result<Option<String>> {
		let mut current_dir = parent.map(|s| s.to_owned()).unwrap_or(self.root_id.clone());

		for p in path.as_ref().components() {
			match p {
				Component::RootDir => current_dir = self.root_id.clone(),
				Component::CurDir => (),
				Component::Normal(osstr) => match osstr.to_str() {
					Some(name) => current_dir = match try!(self.find_child(&current_dir, name)) {
						Some(child) => child,
						None => return Ok(None),
					},
					None => return Err(Error::BadPath),
				},
				_ => return Err(Error::BadPath),
			}
		}

		Ok(Some(current_dir))
	}

	pub fn upload(&mut self, parent: Option<&str>, name: &str, data: &[u8], content_type: Option<mime::Mime>) -> Result<String> {
		#[derive(RustcEncodable)]
		struct UploadMetadata {
			name: String,
			kind: String,
			parents: Vec<String>,
		}

		let calculated_md5 = {
			let mut md5 = Md5::new();
			let mut result = [0u8; 16];
			md5.input(data);
			md5.result(&mut result);
			result.to_hex().to_lowercase()
		};

		let parent = parent.unwrap_or(&self.root_id.clone()).to_owned();

		let metadata = UploadMetadata {
			name: name.to_owned(),
			kind: "FILE".to_owned(),
			parents: vec![parent.to_owned()],
		};

		let content_type = content_type.unwrap_or("application/octect-stream".parse().unwrap());

		let request = RestBuilder::post(&self.endpoint.content_url)
			.url_push("nodes")
			.authorization(&self.authorization.access_token.clone().unwrap())
			.multipart_data("metadata", json::encode(&metadata).unwrap().as_bytes(), None, None)
			.multipart_data("content", data, Some(name.to_owned()), Some(content_type));

		let (status_code, body) = try!(self.get_server_response(request, true, DEFAULT_RETRY));

		match status_code {
			hyper::status::StatusCode::Created => {
				let response: NodeUploadResponse = try!(decode_server_json(&body));

				if response.contentProperties.md5.to_lowercase() != calculated_md5 {
					panic!("UH OH!!!! During an upload Amazon returned a bad MD5. This is very bad. We don't handle this case. Oh dear...");
					// TODO: Handle this by deleting the file and returning an error
				}

				self.insert_into_node_cache(&parent, name, &response.id);

				Ok(response.id)
			},
			hyper::status::StatusCode::Conflict => Err(Error::NodeExists),
			_ => Err(Error::UnknownServerError(format!("Unknown Server Response, probably an error. Status was {}, Body was {:?}", status_code, String::from_utf8(body)))),
		}
	}

	/// Create directory if it doesn't exist.
	/// Returns id for created/existing directory.
	pub fn mkdir(&mut self, parent: Option<&str>, name: &str) -> Result<String> {
		#[derive(RustcEncodable)]
		struct Metadata {
			name: String,
			kind: String,
			parents: Vec<String>,
		}

		#[derive(RustcDecodable)]
		struct Response {
			id: String,
		}

		#[derive(RustcDecodable)]
		#[allow(non_snake_case)]
		struct ConflictResponseInfo {
			nodeId: String,
		}

		#[derive(RustcDecodable)]
		struct ConflictResponse {
			info: ConflictResponseInfo,
		}

		let parent = parent.unwrap_or(&self.root_id.clone()).to_owned();

		if let Some(id) = self.fetch_from_node_cache(&parent, name) {
			return Ok(id);
		}

		let metadata = Metadata {
			name: name.to_owned(),
			kind: "FOLDER".to_owned(),
			parents: vec![parent.to_owned()],
		};

		let request = RestBuilder::post(&self.endpoint.metadata_url)
			.url_push("nodes")
			.authorization(&self.authorization.access_token.clone().unwrap())
			.body(json::encode(&metadata).unwrap().as_bytes());

		let (status_code, body) = try!(self.get_server_response(request, true, DEFAULT_RETRY));

		match status_code {
			hyper::status::StatusCode::Created => {
				let response: Response = try!(decode_server_json(&body));
				self.insert_into_node_cache(&parent, name, &response.id);
				Ok(response.id)
			},
			hyper::status::StatusCode::Conflict => {
				let response: ConflictResponse = try!(decode_server_json(&body));
				self.insert_into_node_cache(&parent, name, &response.info.nodeId);
				Ok(response.info.nodeId)
			},
			_ => Err(Error::UnknownServerError(format!("Unknown Server Response, probably an error. Status was {}, Body was {:?}", status_code, String::from_utf8(body)))),
		}
	}

	/// Create all directories in path if they don't exist
	/// Returns id for the last directory in the path
	pub fn mkdir_all<P: AsRef<Path>>(&mut self, parent: Option<&str>, path: P) -> Result<String> {
		let mut current_dir = parent.map(|s| s.to_owned()).unwrap_or(self.root_id.clone());

		for p in path.as_ref().components() {
			match p {
				Component::RootDir => current_dir = self.root_id.clone(),
				Component::CurDir => (),
				Component::Normal(osstr) => {
					let name = try!(osstr.to_str().ok_or(Error::BadPath));
					current_dir = try!(self.mkdir(Some(&current_dir), name));
				},
				_ => return Err(Error::BadPath),
			}
		}

		Ok(current_dir)
	}

	pub fn ls(&mut self, parent: &str) -> Result<Vec<String>> {
		let mut ids = Vec::new();
		let mut next_token = None;

		loop {
			let request = RestBuilder::get(&self.endpoint.metadata_url)
				.url_push("nodes")
				.url_push(parent)
				.url_push("children")
				.authorization(&self.authorization.access_token.clone().unwrap());
			let request = match next_token {
				Some(token) => request.url_query(&[("startToken", token)]),
				None => request,
			};
			let (status_code, body) = try!(self.get_server_response(request, true, DEFAULT_RETRY));

			let response: NodesResponse = match status_code {
				StatusCode::Ok => {
					try!(decode_server_json(&body))
				},
				_ => return Err(Error::UnknownServerError(format!("Unknown Server Response, probably an error. Status was {}, Body was {:?}", status_code, String::from_utf8(body)))),
			};

			for node in response.data {
				ids.push(node.id.clone())
			}

			match response.nextToken {
				Some(token) => next_token = Some(token),
				None => break,
			}
		}

		Ok(ids)
	}

	pub fn download(&mut self, id: &str) -> Result<Vec<u8>> {
		let request = RestBuilder::get(&self.endpoint.content_url)
			.url_push("nodes").url_push(id).url_push("content")
			.authorization(&self.authorization.access_token.clone().unwrap());
		let (status_code, body) = try!(self.get_server_response(request, true, DEFAULT_RETRY));

		match status_code {
			StatusCode::Ok => Ok(body),
			_ => return Err(Error::UnknownServerError(format!("Unknown Server Response, probably an error. Status was {}, Body was {:?}", status_code, String::from_utf8(body)))),
		}
	}
}


fn read_json_file<T: Decodable>(path: &str) -> Option<T> {
	match File::open(path) {
		Ok(mut f) => {
			let mut s = String::new();
			f.read_to_string(&mut s).unwrap();
			json::decode(&s).unwrap()
		},
		Err(_) => None,
	}
}


fn write_json_file<T: Encodable>(path: &str, value: &T) {
	let mut f = File::create(path).unwrap();
	f.write_all (&json::encode(value).unwrap().into_bytes()).unwrap();
}


fn decode_server_json<T: Decodable>(s: &[u8]) -> Result<T> {
	match String::from_utf8(s.to_vec()) {
		Ok(s) => {
			json::decode(&s).map_err(|e| Error::ResponseBadJson(e))
		},
		Err(_) => {
			Err(Error::ResponseNotUtf8(s.to_vec()))
		},
	}
}


fn open_webbrowser(url: &str) {
	Command::new("xdg-open").arg(url).output().unwrap();
}
