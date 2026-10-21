//! Experimental standalone S3-compatible immutable blob adapter.
//!
//! Server configuration only: no account discovery, environment credentials,
//! document authorization, delete, multipart upload or provider activation.
//! One service must exclusively own the prefix. Listing cannot atomically enforce
//! quotas across independent writers and is not a transaction-consistent backup.
//! Sources: AWS S3 API PutObject/GetObject/ListObjectsV2 and the published SigV4
//! single-chunk authorization specification; no SDK/provider source was adapted.
use crate::{
    Error, MAX_CONTENT, MAX_STORED_CONTENT, MAX_VERSIONS,
    blob_store::{BlobBinding, BlobReceipt, BlobStore},
    digest,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use ureq::RequestExt;

const MAX_XML: usize = 512 * 1024;
const MAX_ERROR: usize = 64 * 1024;
const MAX_TOKEN: usize = 2048;
const MAX_PAGES: usize = MAX_VERSIONS + 1;
const ATTEMPTS: usize = 3;
const OPERATION_BUDGET: Duration = Duration::from_secs(30);
const REQUEST_BUDGET: Duration = Duration::from_secs(10);

/// Storage-only credentials; never reuse a user or connector credential here.
/// Session expiry/rotation is supplied by the server operator, not discovered.
pub struct StorageCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
}

impl std::fmt::Debug for StorageCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("StorageCredentials([redacted])")
    }
}

fn visible(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && value.bytes().all(|byte| (33..=126).contains(&byte))
}

impl StorageCredentials {
    pub fn new(access_key_id: String, secret_access_key: String, session_token: Option<String>) -> Result<Self, Error> {
        if !visible(&access_key_id, 128)
            || !access_key_id.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || !visible(&secret_access_key, 256)
            || session_token.as_ref().is_some_and(|token| !visible(token, 8192))
        {
            return Err(Error::Invalid("S3 storage credentials"));
        }
        Ok(Self { access_key_id, secret_access_key, session_token })
    }
}

/// An explicit HTTPS origin, ordinary bucket and exclusive nonempty key prefix.
/// Only path-style addressing is supported; no access points/directory buckets.
pub struct S3Config {
    origin: String,
    authority: String,
    bucket: String,
    prefix: String,
    region: String,
}
impl std::fmt::Debug for S3Config {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("S3Config([redacted])")
    }
}
impl S3Config {
    pub fn new(endpoint: &str, bucket: &str, owned_prefix: &str, region: &str) -> Result<Self, Error> {
        if endpoint.len() > 2048
            || !endpoint.is_ascii()
            || endpoint.bytes().any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
            || endpoint.contains(['@', '\\', '?', '#', '%'])
        {
            return Err(Error::Invalid("S3 endpoint"));
        }
        let uri: ureq::http::Uri = endpoint.parse().map_err(|_| Error::Invalid("S3 endpoint"))?;
        if uri.scheme_str() != Some("https") || !matches!(uri.path(), "" | "/") {
            return Err(Error::Invalid("S3 HTTPS origin required"));
        }
        let authority = uri.authority().ok_or(Error::Invalid("S3 endpoint authority"))?;
        let host = authority.host();
        if host.is_empty() {
            return Err(Error::Invalid("S3 endpoint authority"));
        }
        let suffix = authority.as_str().strip_prefix(host).ok_or(Error::Invalid("S3 endpoint authority"))?;
        let port = if suffix.is_empty() {
            String::new()
        } else {
            let digits = suffix.strip_prefix(':').ok_or(Error::Invalid("S3 endpoint port"))?;
            if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(Error::Invalid("S3 endpoint port"));
            }
            let port: u16 = digits.parse().map_err(|_| Error::Invalid("S3 endpoint port"))?;
            if port == 0 {
                return Err(Error::Invalid("S3 endpoint port"));
            }
            format!(":{port}")
        };
        if !(3..=63).contains(&bucket.len())
            || !bucket.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.'))
            || !bucket.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
            || !bucket.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
            || bucket.contains("..")
            || bucket.ends_with("--x-s3")
        {
            return Err(Error::Invalid("S3 bucket"));
        }
        if region.is_empty()
            || region.len() > 64
            || !region.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || !region.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
            || !region.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
        {
            return Err(Error::Invalid("S3 region"));
        }
        let prefix = owned_prefix.strip_suffix('/').ok_or(Error::Invalid("S3 owned prefix must end in slash"))?;
        if prefix.is_empty()
            || owned_prefix.len() > 256
            || prefix.split('/').any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
        {
            return Err(Error::Invalid("S3 owned prefix"));
        }
        let authority = format!("{}{port}", host.to_ascii_lowercase());
        Ok(Self { origin: format!("https://{authority}"), authority, bucket: bucket.into(), prefix: owned_prefix.into(), region: region.into() })
    }
    fn path(&self, key: Option<&str>) -> String {
        match key {
            Some(key) => format!("/{}/{}{key}", self.bucket, self.prefix),
            None => format!("/{}", self.bucket),
        }
    }
}

pub struct S3BlobStore {
    config: S3Config,
    credentials: StorageCredentials,
    agent: ureq::Agent,
}
impl std::fmt::Debug for S3BlobStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("S3BlobStore([redacted])")
    }
}

fn transport_error() -> Error {
    Error::Network(std::io::Error::other("S3 storage transport failed"))
}
fn valid_digest(value: &str) -> Result<(), Error> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err(Error::Invalid("S3 blob digest"));
    }
    Ok(())
}
fn remaining(started: Instant) -> Result<Duration, Error> {
    OPERATION_BUDGET.checked_sub(started.elapsed()).filter(|duration| !duration.is_zero()).ok_or(Error::Invalid("S3 operation deadline"))
}

// UTF-8 bytes, never form encoding. Canonical query sorting happens AFTER encoding.
fn encode(value: &str, preserve_slashes: bool) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') || (preserve_slashes && byte == b'/') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}
fn canonical_query(parameters: &[(String, String)]) -> String {
    let mut encoded: Vec<_> = parameters.iter().map(|(key, value)| (encode(key, false), encode(value, false))).collect();
    encoded.sort();
    encoded.into_iter().map(|(key, value)| format!("{key}={value}")).collect::<Vec<_>>().join("&")
}
fn decode(value: &str) -> Result<String, Error> {
    let mut result = Vec::new();
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if byte != b'%' {
            result.push(byte);
            continue;
        }
        let high = bytes.next().and_then(|byte| char::from(byte).to_digit(16)).ok_or(Error::Integrity)?;
        let low = bytes.next().and_then(|byte| char::from(byte).to_digit(16)).ok_or(Error::Integrity)?;
        result.push((high * 16 + low) as u8);
    }
    String::from_utf8(result).map_err(|_| Error::Integrity)
}

fn utc_timestamp(seconds: u64) -> Result<String, Error> {
    if seconds > 253_402_300_799 {
        return Err(Error::Invalid("S3 clock range"));
    }
    let mut days = seconds / 86_400;
    let mut selected = None;
    for year in 1970u64..=9999 {
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let count = if leap { 366 } else { 365 };
        if days >= count {
            days -= count;
            continue;
        }
        for (index, count) in [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31].into_iter().enumerate() {
            if days >= count {
                days -= count;
                continue;
            }
            selected = Some((year, index + 1, days + 1));
            break;
        }
        break;
    }
    let (year, month, day) = selected.ok_or(Error::Invalid("S3 clock range"))?;
    let time = seconds % 86_400;
    Ok(format!("{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z", time / 3600, time % 3600 / 60, time % 60))
}
fn timestamp() -> Result<String, Error> {
    utc_timestamp(SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| Error::Invalid("S3 clock before epoch"))?.as_secs())
}

fn mac(key: &[u8], message: &str) -> Result<Vec<u8>, Error> {
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::Invalid("S3 signing key"))?;
    hmac.update(message.as_bytes());
    Ok(hmac.finalize().into_bytes().to_vec())
}

struct Signed {
    headers: BTreeMap<String, String>,
    query: String,
}
impl std::fmt::Debug for Signed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SignedS3Request([redacted])")
    }
}
// Keep every canonical input explicit for specification-vector tests.
#[allow(clippy::too_many_arguments)]
fn sign(
    credentials: &StorageCredentials,
    region: &str,
    method: &str,
    path: &str,
    query: &[(String, String)],
    mut headers: BTreeMap<String, String>,
    body: &[u8],
    date: &str,
) -> Result<Signed, Error> {
    if date.len() != 16
        || date.get(8..9) != Some("T")
        || date.get(15..16) != Some("Z")
        || !date.bytes().enumerate().all(|(index, byte)| index == 8 || index == 15 || byte.is_ascii_digit())
    {
        return Err(Error::Invalid("S3 signature date"));
    }
    let day = date.get(..8).ok_or(Error::Invalid("S3 signature date"))?;
    let payload = digest(body);
    headers.insert("x-amz-date".into(), date.into());
    headers.insert("x-amz-content-sha256".into(), payload.clone());
    if let Some(token) = &credentials.session_token {
        headers.insert("x-amz-security-token".into(), token.clone());
    }
    let query = canonical_query(query);
    let signed_headers = headers.keys().cloned().collect::<Vec<_>>().join(";");
    let canonical_headers: String =
        headers.iter().map(|(key, value)| format!("{key}:{}\n", value.split_ascii_whitespace().collect::<Vec<_>>().join(" "))).collect();
    let canonical = format!("{method}\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload}");
    let scope = format!("{day}/{region}/s3/aws4_request");
    let to_sign = format!("AWS4-HMAC-SHA256\n{date}\n{scope}\n{}", digest(canonical.as_bytes()));
    let key = mac(format!("AWS4{}", credentials.secret_access_key).as_bytes(), day)?;
    let key = mac(&key, region)?;
    let key = mac(&key, "s3")?;
    let key = mac(&key, "aws4_request")?;
    let signature = mac(&key, &to_sign)?.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    headers.insert(
        "authorization".into(),
        format!("AWS4-HMAC-SHA256 Credential={}/{scope},SignedHeaders={signed_headers},Signature={signature}", credentials.access_key_id),
    );
    Ok(Signed { headers, query })
}

struct Reply {
    status: u16,
    body: Vec<u8>,
}
impl S3BlobStore {
    pub fn new(config: S3Config, credentials: StorageCredentials) -> Result<Self, Error> {
        Self::with_roots(config, credentials, ureq::tls::RootCerts::PlatformVerifier)
    }
    pub fn with_ca(config: S3Config, credentials: StorageCredentials, ca_der: &[u8]) -> Result<Self, Error> {
        if ca_der.is_empty() || ca_der.len() > 64 * 1024 {
            return Err(Error::Invalid("S3 CA size"));
        }
        let mut validation = rustls::RootCertStore::empty();
        validation.add(rustls::pki_types::CertificateDer::from(ca_der.to_vec())).map_err(|_| Error::Invalid("S3 CA certificate"))?;
        let certificate = ureq::tls::Certificate::from_der(ca_der).to_owned();
        Self::with_roots(config, credentials, ureq::tls::RootCerts::new_with_certs(&[certificate]))
    }
    fn with_roots(config: S3Config, credentials: StorageCredentials, roots: ureq::tls::RootCerts) -> Result<Self, Error> {
        let tls = ureq::tls::TlsConfig::builder()
            .root_certs(roots)
            .unversioned_rustls_crypto_provider(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
            .build();
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .tls_config(tls)
            .https_only(true)
            .proxy(None)
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_connect(Some(Duration::from_secs(3)))
            .timeout_global(Some(REQUEST_BUDGET))
            .user_agent("SolidCraft PDM storage")
            .build()
            .into();
        Ok(Self { config, credentials, agent })
    }
    fn exchange(
        &self,
        method: &str,
        key: Option<&str>,
        parameters: &[(String, String)],
        body: &[u8],
        limit: usize,
        started: Instant,
    ) -> Result<Reply, Error> {
        let path = encode(&self.config.path(key), true);
        let mut headers = BTreeMap::from([("host".into(), self.config.authority.clone())]);
        if method == "PUT" {
            headers.insert("if-none-match".into(), "*".into());
            headers.insert("content-type".into(), "application/octet-stream".into());
        }
        let signed = sign(&self.credentials, &self.config.region, method, &path, parameters, headers, body, &timestamp()?)?;
        let url = format!("{}{path}{}", self.config.origin, if signed.query.is_empty() { String::new() } else { format!("?{}", signed.query) });
        let mut builder = ureq::http::Request::builder().method(method).uri(url).header("content-length", body.len());
        for (name, value) in signed.headers {
            let mut value = ureq::http::HeaderValue::from_str(&value).map_err(|_| Error::Invalid("S3 request headers"))?;
            if matches!(name.as_str(), "authorization" | "x-amz-security-token") {
                value.set_sensitive(true);
            }
            builder = builder.header(name, value);
        }
        let request = builder.body(body).map_err(|_| Error::Invalid("S3 request construction"))?;
        let mut response = request
            .with_agent(&self.agent)
            .configure()
            .timeout_global(Some(remaining(started)?.min(REQUEST_BUDGET)))
            .run()
            .map_err(|_| transport_error())?;
        let status = response.status().as_u16();
        if response.headers().contains_key("content-encoding") {
            return Err(Error::Invalid("S3 encoded response unsupported"));
        }
        let cap = if status == 200 { limit } else { MAX_ERROR };
        let body = response.body_mut().with_config().limit(cap as u64).read_to_vec().map_err(|_| transport_error())?;
        Ok(Reply { status, body })
    }
    fn pause(attempt: usize, started: Instant) -> Result<(), Error> {
        let pause = Duration::from_millis(25 * (attempt as u64 + 1));
        if remaining(started)? <= pause {
            return Err(Error::Invalid("S3 operation deadline"));
        }
        std::thread::sleep(pause);
        Ok(())
    }
    fn get(&self, sha256: &str, started: Instant) -> Result<Vec<u8>, Error> {
        valid_digest(sha256)?;
        for attempt in 0..ATTEMPTS {
            match self.exchange("GET", Some(sha256), &[], &[], MAX_CONTENT, started) {
                Ok(reply) if reply.status == 200 => {
                    if digest(&reply.body) != sha256 {
                        return Err(Error::Integrity);
                    }
                    return Ok(reply.body);
                }
                Ok(reply) if reply.status == 404 => return Err(Error::NotFound),
                Ok(reply) if reply.status == 403 => return Err(Error::Forbidden),
                Ok(reply) if matches!(reply.status, 500 | 502 | 503 | 504) && attempt + 1 < ATTEMPTS => {}
                Err(Error::Network(_)) if attempt + 1 < ATTEMPTS => {}
                Err(error) => return Err(error),
                _ => return Err(Error::Invalid("S3 GET response")),
            }
            Self::pause(attempt, started)?;
        }
        Err(transport_error())
    }
    fn inventory_at(&self, started: Instant) -> Result<Vec<BlobReceipt>, Error> {
        let mut inventory = Vec::new();
        let mut hashes = BTreeSet::new();
        let mut tokens = BTreeSet::new();
        let mut token: Option<String> = None;
        let mut total = 0u64;
        for _ in 0..MAX_PAGES {
            let mut parameters = vec![
                ("list-type".into(), "2".into()),
                ("prefix".into(), self.config.prefix.clone()),
                ("encoding-type".into(), "url".into()),
                ("max-keys".into(), (MAX_VERSIONS + 1).to_string()),
            ];
            if let Some(token) = &token {
                parameters.push(("continuation-token".into(), token.clone()));
            }
            let mut page = None;
            for attempt in 0..ATTEMPTS {
                match self.exchange("GET", None, &parameters, &[], MAX_XML, started) {
                    Ok(reply) if reply.status == 200 => {
                        page = Some(parse_page(&reply.body, &self.config, token.as_deref())?);
                        break;
                    }
                    Ok(reply) if reply.status == 403 => return Err(Error::Forbidden),
                    Ok(reply) if matches!(reply.status, 500 | 502 | 503 | 504) && attempt + 1 < ATTEMPTS => {}
                    Err(Error::Network(_)) if attempt + 1 < ATTEMPTS => {}
                    Err(error) => return Err(error),
                    _ => return Err(Error::Invalid("S3 inventory response")),
                }
                Self::pause(attempt, started)?;
            }
            let page = page.ok_or_else(transport_error)?;
            for blob in page.blobs {
                if inventory.len() >= MAX_VERSIONS || !hashes.insert(blob.sha256.clone()) {
                    return Err(Error::Invalid("S3 inventory count or duplicate"));
                }
                total = total.checked_add(blob.bytes).ok_or(Error::Integrity)?;
                if blob.bytes > MAX_CONTENT as u64 || total > MAX_STORED_CONTENT {
                    return Err(Error::Invalid("S3 inventory size"));
                }
                inventory.push(blob);
            }
            match page.next {
                Some(next) => {
                    if !tokens.insert(next.clone()) {
                        return Err(Error::Integrity);
                    }
                    token = Some(next);
                }
                None => {
                    // The filesystem adapter verifies every orphan too; preserve that contract.
                    for blob in &inventory {
                        if self.get(&blob.sha256, started)?.len() as u64 != blob.bytes {
                            return Err(Error::Integrity);
                        }
                    }
                    inventory.sort_by(|left, right| left.sha256.cmp(&right.sha256));
                    return Ok(inventory);
                }
            }
        }
        Err(Error::Invalid("S3 inventory page limit"))
    }
}

impl BlobStore for S3BlobStore {
    fn binding(&self) -> BlobBinding {
        use sha2::Digest;
        let mut hash = sha2::Sha256::new();
        hash.update(b"solidcraft-pdm-s3-binding-v1\0");
        for value in [&self.config.origin, &self.config.bucket, &self.config.prefix, &self.config.region] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value.as_bytes());
        }
        BlobBinding::External { fingerprint: format!("{:x}", hash.finalize()) }
    }
    fn put_verified_if_absent(&mut self, sha256: &str, content: &[u8]) -> Result<BlobReceipt, Error> {
        valid_digest(sha256)?;
        if content.len() > MAX_CONTENT {
            return Err(Error::Invalid("S3 content size"));
        }
        if digest(content) != sha256 {
            return Err(Error::Integrity);
        }
        let started = Instant::now();
        let inventory = self.inventory_at(started)?;
        let receipt = BlobReceipt { sha256: sha256.into(), bytes: content.len() as u64 };
        if inventory.iter().any(|blob| blob.sha256 == sha256) {
            if self.get(sha256, started)? != content {
                return Err(Error::Integrity);
            }
            return Ok(receipt);
        }
        let bytes = inventory.iter().try_fold(content.len() as u64, |total, blob| total.checked_add(blob.bytes).ok_or(Error::Integrity))?;
        if inventory.len() >= MAX_VERSIONS || bytes > MAX_STORED_CONTENT {
            return Err(Error::Invalid("S3 blob quota"));
        }
        for attempt in 0..ATTEMPTS {
            match self.exchange("PUT", Some(sha256), &[], content, MAX_ERROR, started) {
                Ok(reply) if matches!(reply.status, 200 | 412) => {
                    if self.get(sha256, started)? != content {
                        return Err(Error::Integrity);
                    }
                    return Ok(receipt);
                }
                Ok(reply) if reply.status == 409 && error_code(&reply.body)? == "ConditionalRequestConflict" && attempt + 1 < ATTEMPTS => {}
                Ok(reply) if matches!(reply.status, 500 | 502 | 503 | 504) && attempt + 1 < ATTEMPTS => {}
                Ok(reply) if reply.status == 403 => return Err(Error::Forbidden),
                Err(Error::Network(_)) if attempt + 1 < ATTEMPTS => {}
                Err(error) => return Err(error),
                _ => return Err(Error::Invalid("S3 conditional PUT response")),
            }
            Self::pause(attempt, started)?;
        }
        Err(transport_error())
    }
    fn get_verified(&self, sha256: &str) -> Result<Vec<u8>, Error> {
        self.get(sha256, Instant::now())
    }
    fn inventory(&self) -> Result<Vec<BlobReceipt>, Error> {
        self.inventory_at(Instant::now())
    }
}

#[derive(Default)]
struct Node {
    name: String,
    text: String,
    children: Vec<Node>,
}
fn node(start: &quick_xml::events::BytesStart<'_>) -> Result<Node, Error> {
    let name = std::str::from_utf8(start.name().as_ref()).map_err(|_| Error::Integrity)?.to_owned();
    if name.contains(':') {
        return Err(Error::Invalid("S3 XML prefixed elements unsupported"));
    }
    for attribute in start.attributes() {
        let attribute = attribute.map_err(|_| Error::Integrity)?;
        if attribute.key.as_ref() != b"xmlns" || attribute.value.as_ref() != b"http://s3.amazonaws.com/doc/2006-03-01/" {
            return Err(Error::Invalid("S3 XML attributes"));
        }
    }
    Ok(Node { name, ..Node::default() })
}
fn xml(bytes: &[u8]) -> Result<Node, Error> {
    use quick_xml::events::Event;
    if bytes.len() > MAX_XML {
        return Err(Error::Invalid("S3 XML size"));
    }
    let mut reader = quick_xml::Reader::from_reader(bytes);
    let mut stack: Vec<Node> = Vec::new();
    let mut root = None;
    let mut events = 0;
    loop {
        events += 1;
        if events > 16_384 {
            return Err(Error::Invalid("S3 XML event count"));
        }
        match reader.read_event().map_err(|_| Error::Integrity)? {
            Event::Start(start) => {
                if stack.len() >= 8 {
                    return Err(Error::Invalid("S3 XML depth"));
                }
                stack.push(node(&start)?);
            }
            Event::Empty(start) => {
                if stack.len() >= 8 {
                    return Err(Error::Invalid("S3 XML depth"));
                }
                let item = node(&start)?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(item);
                } else if root.replace(item).is_some() {
                    return Err(Error::Integrity);
                }
            }
            Event::End(end) => {
                let item = stack.pop().ok_or(Error::Integrity)?;
                if item.name.as_bytes() != end.name().as_ref() {
                    return Err(Error::Integrity);
                }
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(item);
                } else if root.replace(item).is_some() {
                    return Err(Error::Integrity);
                }
            }
            Event::Text(text) => {
                let text = text.decode().map_err(|_| Error::Integrity)?;
                if let Some(item) = stack.last_mut() {
                    item.text.push_str(&text);
                } else if !text.trim().is_empty() {
                    return Err(Error::Integrity);
                }
            }
            Event::GeneralRef(reference) => {
                let value = if let Some(value) = reference.resolve_char_ref().map_err(|_| Error::Integrity)? {
                    value
                } else {
                    match reference.decode().map_err(|_| Error::Integrity)?.as_ref() {
                        "amp" => '&',
                        "lt" => '<',
                        "gt" => '>',
                        "quot" => '"',
                        "apos" => '\'',
                        _ => return Err(Error::Invalid("S3 XML entity")),
                    }
                };
                stack.last_mut().ok_or(Error::Integrity)?.text.push(value);
            }
            Event::Decl(_) | Event::Comment(_) => {}
            Event::Eof => break,
            _ => return Err(Error::Invalid("S3 XML declaration or event")),
        }
    }
    if !stack.is_empty() {
        return Err(Error::Integrity);
    }
    root.ok_or(Error::Integrity)
}
fn one<'a>(node: &'a Node, name: &str) -> Result<Option<&'a str>, Error> {
    let mut matches = node.children.iter().filter(|child| child.name == name);
    let first = matches.next();
    if matches.next().is_some() || first.is_some_and(|item| !item.children.is_empty()) {
        return Err(Error::Integrity);
    }
    Ok(first.map(|item| item.text.as_str()))
}
fn required<'a>(node: &'a Node, name: &str) -> Result<&'a str, Error> {
    one(node, name)?.ok_or(Error::Integrity)
}
fn error_code(body: &[u8]) -> Result<String, Error> {
    let root = xml(body)?;
    if root.name != "Error" {
        return Err(Error::Integrity);
    }
    Ok(required(&root, "Code")?.into())
}
struct Page {
    blobs: Vec<BlobReceipt>,
    next: Option<String>,
}
fn parse_page(body: &[u8], config: &S3Config, sent_token: Option<&str>) -> Result<Page, Error> {
    let root = xml(body)?;
    if root.name != "ListBucketResult"
        || required(&root, "Name")? != config.bucket
        || required(&root, "EncodingType")? != "url"
        || decode(required(&root, "Prefix")?)? != config.prefix
        || root.children.iter().any(|child| child.name == "CommonPrefixes")
    {
        return Err(Error::Integrity);
    }
    if !root.text.trim().is_empty()
        || root.children.iter().any(|child| {
            !matches!(
                child.name.as_str(),
                "Name"
                    | "Prefix"
                    | "KeyCount"
                    | "MaxKeys"
                    | "IsTruncated"
                    | "EncodingType"
                    | "ContinuationToken"
                    | "NextContinuationToken"
                    | "Contents"
            )
        })
    {
        return Err(Error::Integrity);
    }
    if let Some(token) = one(&root, "ContinuationToken")?
        && Some(token) != sent_token
    {
        return Err(Error::Integrity);
    }
    let truncated = match required(&root, "IsTruncated")? {
        "true" => true,
        "false" => false,
        _ => return Err(Error::Integrity),
    };
    let next = one(&root, "NextContinuationToken")?;
    if (truncated && next.is_none_or(|token| token.is_empty() || token.len() > MAX_TOKEN || token.chars().any(char::is_control)))
        || (!truncated && next.is_some())
    {
        return Err(Error::Integrity);
    }
    let mut blobs = Vec::new();
    for item in root.children.iter().filter(|child| child.name == "Contents") {
        if !item.text.trim().is_empty()
            || item.children.iter().any(|child| {
                !matches!(
                    child.name.as_str(),
                    "Key" | "Size" | "LastModified" | "ETag" | "ChecksumAlgorithm" | "ChecksumType" | "Owner" | "StorageClass" | "RestoreStatus"
                )
            })
        {
            return Err(Error::Integrity);
        }
        if blobs.len() > MAX_VERSIONS {
            return Err(Error::Invalid("S3 inventory page count"));
        }
        let key = decode(required(item, "Key")?)?;
        let hash = key.strip_prefix(&config.prefix).ok_or(Error::Integrity)?;
        valid_digest(hash).map_err(|_| Error::Integrity)?;
        let size = required(item, "Size")?;
        if size.is_empty() || !size.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(Error::Integrity);
        }
        let bytes: u64 = size.parse().map_err(|_| Error::Integrity)?;
        if bytes > MAX_CONTENT as u64 {
            return Err(Error::Invalid("S3 inventory object size"));
        }
        blobs.push(BlobReceipt { sha256: hash.into(), bytes });
    }
    if let Some(count) = one(&root, "KeyCount")?
        && count.parse::<usize>().map_err(|_| Error::Integrity)? != blobs.len()
    {
        return Err(Error::Integrity);
    }
    if let Some(maximum) = one(&root, "MaxKeys")?
        && maximum.parse::<usize>().map_err(|_| Error::Integrity)? > MAX_VERSIONS + 1
    {
        return Err(Error::Integrity);
    }
    Ok(Page { blobs, next: next.map(str::to_owned) })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    #[test]
    fn binding_is_derived_from_storage_location_not_credentials() {
        let config = || S3Config::new("https://example.test", "toy-bucket", "owned/", "us-test-1").unwrap();
        let first = S3BlobStore::new(config(), StorageCredentials::new("access-a".into(), "secret-a".into(), None).unwrap()).unwrap();
        let second = S3BlobStore::new(config(), StorageCredentials::new("access-b".into(), "secret-b".into(), None).unwrap()).unwrap();
        assert_eq!(first.binding(), second.binding());
        let moved = S3BlobStore::new(
            S3Config::new("https://example.test", "toy-bucket", "other/", "us-test-1").unwrap(),
            StorageCredentials::new("access-a".into(), "secret-a".into(), None).unwrap(),
        )
        .unwrap();
        assert_ne!(first.binding(), moved.binding());
    }
    use crate::http_listener::{Handler, HttpListener, HttpsConfig, Reply as HttpReply};
    use http_body_util::{BodyExt, Full, Limited};
    use hyper::{Response as HttpResponse, body::Bytes};
    use std::sync::{Arc, Mutex};

    const ACCESS: &str = "LOCALTESTACCESS";
    const SECRET: &str = "local-only-secret-storage-key";
    const SESSION: &str = "local-only-session-token";
    const CA: &[u8] = include_bytes!("../tests/fixtures/pdm-https/ca.der");
    const CERT: &[u8] = include_bytes!("../tests/fixtures/pdm-https/server.der");
    const KEY: &[u8] = include_bytes!("../tests/fixtures/pdm-https/server-key.der");
    fn credentials() -> StorageCredentials {
        StorageCredentials::new(ACCESS.into(), SECRET.into(), Some(SESSION.into())).unwrap()
    }
    fn config(endpoint: &str) -> S3Config {
        S3Config::new(endpoint, "toy-bucket", "vault-one/blobs/", "us-east-1").unwrap()
    }

    #[test]
    fn published_aws_get_vector_matches_expected_signature() {
        // AWS's public "Example: GET Object" vector. Expected signature is
        // published by AWS, not generated by this signer or another local helper.
        // https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html
        let credentials = StorageCredentials::new("AKIAIOSFODNN7EXAMPLE".into(), "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(), None).unwrap();
        let signed = sign(
            &credentials,
            "us-east-1",
            "GET",
            "/test.txt",
            &[],
            BTreeMap::from([("host".into(), "examplebucket.s3.amazonaws.com".into()), ("range".into(), "bytes=0-9".into())]),
            &[],
            "20130524T000000Z",
        )
        .unwrap();
        assert!(signed.headers.get("authorization").unwrap().ends_with("Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"));
        assert!(signed.headers.get("authorization").unwrap().contains("SignedHeaders=host;range;x-amz-content-sha256;x-amz-date"));
    }

    #[test]
    fn canonical_encoding_utc_and_configuration_are_bounded() {
        assert_eq!(encode("a b+c/é", false), "a%20b%2Bc%2F%C3%A9");
        assert_eq!(encode("/a//b", true), "/a//b");
        assert_eq!(
            canonical_query(&[("prefix".into(), "v/".into()), ("continuation-token".into(), "a+/= b".into())]),
            "continuation-token=a%2B%2F%3D%20b&prefix=v%2F"
        );
        assert_eq!(decode("a%2B%2F%3D%20b").unwrap(), "a+/= b");
        assert!(decode("%GG").is_err());
        assert_eq!(utc_timestamp(0).unwrap(), "19700101T000000Z");
        assert_eq!(utc_timestamp(951_782_400).unwrap(), "20000229T000000Z");
        assert_eq!(utc_timestamp(253_402_300_799).unwrap(), "99991231T235959Z");
        assert!(utc_timestamp(u64::MAX).is_err());
        for endpoint in [
            "http://localhost",
            "https://user:secret@localhost",
            "https://localhost/prefix",
            "https://localhost?x=y",
            "https://localhost:0",
            "https://localhost/#x",
        ] {
            assert!(S3Config::new(endpoint, "bucket", "vault/blobs/", "us-east-1").is_err());
        }
        for prefix in ["", "/", "other", "../", "vault//blobs/", "/vault/", "vault/%2e/", "vault\\blobs/"] {
            assert!(S3Config::new("https://localhost", "bucket", prefix, "us-east-1").is_err());
        }
        assert!(StorageCredentials::new("access".into(), "secret\n".into(), None).is_err());
        let secret = credentials();
        let setup = config("https://localhost");
        assert!(!format!("{secret:?} {setup:?}").contains(SECRET));
        let store = S3BlobStore::new(setup, secret).unwrap();
        let options = store.agent.config();
        assert!(options.https_only());
        assert!(options.proxy().is_none());
        assert_eq!(options.max_redirects(), 0);
        for secret in [ACCESS, SECRET, SESSION] {
            assert!(!format!("{store:?} {:?}", transport_error()).contains(secret));
        }
        assert!(S3BlobStore::with_ca(config("https://localhost"), credentials(), b"not DER").is_err());
    }

    fn listing(contents: &str, tail: &str) -> Vec<u8> {
        format!("<?xml version=\"1.0\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>toy-bucket</Name><Prefix>vault-one%2Fblobs%2F</Prefix><EncodingType>url</EncodingType>{contents}{tail}</ListBucketResult>").into_bytes()
    }
    fn item(hash: &str, bytes: usize) -> String {
        format!("<Contents><Key>vault-one%2Fblobs%2F{hash}</Key><Size>{bytes}</Size><ETag>opaque-not-a-sha256</ETag></Contents>")
    }

    #[test]
    fn xml_pages_reject_foreign_keys_entities_duplicates_depth_and_bad_pagination() {
        let config = config("https://localhost");
        let hash = digest(b"toy");
        let valid = listing(&item(&hash, 3), "<IsTruncated>false</IsTruncated>");
        assert_eq!(parse_page(&valid, &config, None).unwrap().blobs, vec![BlobReceipt { sha256: hash.clone(), bytes: 3 }]);
        let invalid = [
            listing(&item(&hash, 3).replace("vault-one%2F", "vault-two%2F"), "<IsTruncated>false</IsTruncated>"),
            listing(&item("bad", 3), "<IsTruncated>false</IsTruncated>"),
            listing(&item(&hash, MAX_CONTENT + 1), "<IsTruncated>false</IsTruncated>"),
            listing("", "<IsTruncated>true</IsTruncated>"),
            listing("", "<IsTruncated>false</IsTruncated><NextContinuationToken>unexpected</NextContinuationToken>"),
            listing("", "<IsTruncated>false</IsTruncated><IsTruncated>true</IsTruncated>"),
            listing("<CommonPrefixes><Prefix>hidden/</Prefix></CommonPrefixes>", "<IsTruncated>false</IsTruncated>"),
            listing("<Unknown><Contents/></Unknown>", "<IsTruncated>false</IsTruncated>"),
            listing("", "<IsTruncated>true</IsTruncated><NextContinuationToken>&external;</NextContinuationToken>"),
            b"<!DOCTYPE root [<!ENTITY external SYSTEM 'file:///private'>]><ListBucketResult/>".to_vec(),
            format!("{}{}", "<x>".repeat(9), "</x>".repeat(9)).into_bytes(),
            b"<ListBucketResult>not completed".to_vec(),
        ];
        for page in invalid {
            assert!(parse_page(&page, &config, None).is_err());
        }
        let page =
            parse_page(&listing("", "<IsTruncated>true</IsTruncated><NextContinuationToken>a+/= b&amp;c</NextContinuationToken>"), &config, None)
                .unwrap();
        assert_eq!(page.next.as_deref(), Some("a+/= b&c"));
        assert!(xml(&vec![b'x'; MAX_XML + 1]).is_err());
    }

    #[derive(Clone, Copy, Default)]
    enum Fault {
        #[default]
        None,
        ConflictOnce,
        LostAcknowledgementOnce,
        ExistingRace,
        CorruptExistingRace,
        DuplicateInventory,
        RepeatedToken,
        Redirect,
        OversizedGet,
        ObjectQuota,
        ByteQuota,
    }
    #[derive(Default)]
    struct MockState {
        objects: BTreeMap<String, Vec<u8>>,
        put_attempts: usize,
        conditional: usize,
        signed: usize,
        fault: Fault,
        paths: Vec<String>,
    }
    struct Mock {
        listener: HttpListener,
        state: Arc<Mutex<MockState>>,
    }
    fn reply(status: u16, bytes: Vec<u8>) -> HttpReply {
        HttpResponse::builder().status(status).body(Full::new(Bytes::from(bytes))).unwrap()
    }
    impl Mock {
        fn new(fault: Fault) -> Self {
            let state = Arc::new(Mutex::new(MockState { fault, ..MockState::default() }));
            let shared = state.clone();
            let handler: Handler = Arc::new(move |request| {
                let shared = shared.clone();
                Box::pin(async move {
                    let method = request.method().clone();
                    let uri = request.uri().clone();
                    let headers = request.headers().clone();
                    let body = Limited::new(request.into_body(), MAX_CONTENT + 1).collect().await.unwrap().to_bytes();
                    let mut state = shared.lock().unwrap();
                    state.paths.push(uri.to_string());
                    let signed = headers
                        .get("authorization")
                        .and_then(|header| header.to_str().ok())
                        .is_some_and(|header| header.starts_with(&format!("AWS4-HMAC-SHA256 Credential={ACCESS}/")))
                        && headers.get("x-amz-security-token").and_then(|header| header.to_str().ok()) == Some(SESSION)
                        && headers.get("x-amz-content-sha256").and_then(|header| header.to_str().ok()) == Some(digest(&body).as_str());
                    if !signed {
                        return reply(403, b"<Error><Code>SignatureDoesNotMatch</Code></Error>".to_vec());
                    }
                    state.signed += 1;
                    if matches!(state.fault, Fault::Redirect) {
                        return HttpResponse::builder()
                            .status(307)
                            .header("location", "https://elsewhere.invalid/private")
                            .body(Full::new(Bytes::new()))
                            .unwrap();
                    }
                    if method == "GET" && uri.path() == "/toy-bucket" {
                        let query = uri.query().unwrap_or_default();
                        assert!(
                            query.contains("list-type=2") && query.contains("prefix=vault-one%2Fblobs%2F") && query.contains("encoding-type=url")
                        );
                        if matches!(state.fault, Fault::RepeatedToken) {
                            return reply(
                                200,
                                listing("", "<IsTruncated>true</IsTruncated><NextContinuationToken>same+/=token</NextContinuationToken>"),
                            );
                        }
                        if matches!(state.fault, Fault::ObjectQuota | Fault::ByteQuota) {
                            let (count, size) = if matches!(state.fault, Fault::ObjectQuota) {
                                (MAX_VERSIONS + 1, 0)
                            } else {
                                (MAX_STORED_CONTENT as usize / MAX_CONTENT + 1, MAX_CONTENT)
                            };
                            let contents: String = (0..count).map(|index| item(&digest(index.to_string().as_bytes()), size)).collect();
                            return reply(200, listing(&contents, "<IsTruncated>false</IsTruncated>"));
                        }
                        let mut contents = String::new();
                        for (hash, bytes) in &state.objects {
                            contents.push_str(&item(hash, bytes.len()));
                        }
                        if matches!(state.fault, Fault::DuplicateInventory) {
                            contents.push_str(&contents.clone());
                        }
                        return reply(200, listing(&contents, "<IsTruncated>false</IsTruncated>"));
                    }
                    let Some(hash) = uri.path().strip_prefix("/toy-bucket/vault-one/blobs/") else { return reply(403, Vec::new()) };
                    if method == "GET" {
                        if matches!(state.fault, Fault::OversizedGet) {
                            return reply(200, vec![0; MAX_CONTENT + 1]);
                        }
                        return match state.objects.get(hash) {
                            Some(bytes) => reply(200, bytes.clone()),
                            None => reply(404, b"<Error><Code>NoSuchKey</Code></Error>".to_vec()),
                        };
                    }
                    if method != "PUT" {
                        return reply(405, Vec::new());
                    }
                    state.put_attempts += 1;
                    if headers.get("if-none-match").and_then(|header| header.to_str().ok()) != Some("*") {
                        return reply(403, Vec::new());
                    }
                    assert!(headers.get("authorization").unwrap().to_str().unwrap().contains("if-none-match"));
                    state.conditional += 1;
                    if matches!(state.fault, Fault::ConflictOnce) {
                        state.fault = Fault::None;
                        return reply(409, b"<Error><Code>ConditionalRequestConflict</Code></Error>".to_vec());
                    }
                    if matches!(state.fault, Fault::ExistingRace | Fault::CorruptExistingRace) {
                        let bytes = if matches!(state.fault, Fault::CorruptExistingRace) { b"wrong existing bytes".to_vec() } else { body.to_vec() };
                        state.objects.insert(hash.into(), bytes);
                        state.fault = Fault::None;
                        return reply(412, Vec::new());
                    }
                    if state.objects.contains_key(hash) {
                        return reply(412, Vec::new());
                    }
                    state.objects.insert(hash.into(), body.to_vec());
                    if matches!(state.fault, Fault::LostAcknowledgementOnce) {
                        state.fault = Fault::None;
                        // Commit first, then deliberately truncate the declared response.
                        return HttpResponse::builder().status(200).header("content-length", "16").body(Full::new(Bytes::new())).unwrap();
                    }
                    reply(200, Vec::new())
                })
            });
            let tls = HttpsConfig::from_der("127.0.0.1:0".parse().unwrap(), vec![CERT.to_vec()], KEY.to_vec()).unwrap();
            let listener = HttpListener::start(tls, handler, 4, Duration::from_secs(5)).unwrap();
            Self { listener, state }
        }
        fn store(&self) -> S3BlobStore {
            S3BlobStore::with_ca(config(&format!("https://{}", self.listener.address())), credentials(), CA).unwrap()
        }
    }

    #[test]
    fn https_mock_roundtrip_immutable_put_inventory_and_fault_reconciliation() {
        for fault in [Fault::None, Fault::ConflictOnce, Fault::LostAcknowledgementOnce, Fault::ExistingRace] {
            let mock = Mock::new(fault);
            let mut store = mock.store();
            let content = b"public-safe original toy blob";
            let hash = digest(content);
            let receipt = store.put_verified_if_absent(&hash, content).unwrap();
            assert_eq!(receipt.bytes, content.len() as u64);
            assert_eq!(store.get_verified(&hash).unwrap(), content);
            assert_eq!(store.put_verified_if_absent(&hash, content).unwrap(), receipt);
            assert_eq!(store.inventory().unwrap(), vec![receipt]);
            let state = mock.state.lock().unwrap();
            assert_eq!(state.objects.len(), 1);
            assert_eq!(state.conditional, state.put_attempts);
            assert!(state.signed > state.put_attempts);
            assert!(state.paths.iter().all(|path| path.starts_with("/toy-bucket?") || path.starts_with("/toy-bucket/vault-one/blobs/")));
        }
    }

    #[test]
    fn mock_rejects_corruption_duplicate_or_unbounded_inventory_and_redirects() {
        let hash = digest(b"toy");
        let mock = Mock::new(Fault::CorruptExistingRace);
        assert!(matches!(mock.store().put_verified_if_absent(&hash, b"toy"), Err(Error::Integrity)));
        let mock = Mock::new(Fault::DuplicateInventory);
        mock.state.lock().unwrap().objects.insert(hash.clone(), b"toy".to_vec());
        assert!(mock.store().inventory().is_err());
        let mock = Mock::new(Fault::RepeatedToken);
        assert!(mock.store().inventory().is_err());
        assert!(mock.state.lock().unwrap().paths.iter().any(|path| path.contains("continuation-token=same%2B%2F%3Dtoken")));
        let mock = Mock::new(Fault::Redirect);
        assert!(mock.store().get_verified(&hash).is_err());
        assert_eq!(mock.state.lock().unwrap().paths.len(), 1);
        let mock = Mock::new(Fault::OversizedGet);
        assert!(mock.store().get_verified(&hash).is_err());
        for fault in [Fault::ObjectQuota, Fault::ByteQuota] {
            let mock = Mock::new(fault);
            assert!(mock.store().put_verified_if_absent(&hash, b"toy").is_err());
            let state = mock.state.lock().unwrap();
            assert_eq!(state.put_attempts, 0);
            assert_eq!(state.paths.len(), 1);
        }
        let mock = Mock::new(Fault::None);
        let mut store = mock.store();
        assert!(store.put_verified_if_absent(&hash, b"wrong bytes").is_err());
        assert!(mock.state.lock().unwrap().paths.is_empty());
    }
}
