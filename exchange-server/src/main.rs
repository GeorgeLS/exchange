use actix_cors::Cors;
use actix_multipart::form::json::Json as MpJson;
use actix_multipart::form::tempfile::TempFile;
use actix_multipart::form::{MultipartForm, MultipartFormConfig};
use actix_web::http::header::{ContentDisposition, ContentType, CONTENT_TYPE};
use actix_web::http::StatusCode;
use actix_web::middleware::Logger;
use actix_web::web::Bytes;
use actix_web::{get, post, App, HttpServer, Responder, ResponseError};
use actix_web::{web, HttpResponse};
use aes_gcm::aead::consts::U12;
use aes_gcm::aead::Aead;
use aes_gcm::aes::Aes256;
use aes_gcm::{
    aead::{AeadCore, KeyInit, OsRng}, Aes256Gcm, AesGcm, Key,
    Nonce,
};
use askama::Template;
use askama_web::WebTemplate;
use async_zip::error::ZipError;
use async_zip::tokio::write::ZipFileWriter;
use async_zip::{Compression, ZipEntryBuilder};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use clap::Parser;
use env_logger::Env;
use log::{error, warn};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{pem, CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio_stream::StreamExt;
use tokio_util::compat::FuturesAsyncWriteCompatExt;
use uuid::Uuid;

const MAX_UPLOAD_SIZE: usize = 200 * 1024 * 1024 * 1024; // 200 GB
const MAX_MEMORY_UPLOAD_SIZE: usize = 500 * 1024 * 1024; // 500 MB
const MAX_STREAM_CHUNK_SIZE: usize = 8 * 1024; // 8 KB

#[derive(Debug, Error)]
enum Error {
    #[error("Bad request. You specified an empty path in your metadata for file '{0}'")]
    EmptyMetadata(String),
    #[error("Bad request. File '{0}' is empty")]
    EmptyFile(String),
    #[error("Bad request. You provided an empty path in the URL")]
    EmptyPathComponent,
    #[error("No upload point for '{0}' was found. Make sure to call /init-upload first")]
    UploadPointNotFound(Uuid),
    #[error("A ZIP error occurred while compressing files: {0}")]
    Zip(#[from] ZipError),
    #[error("An IO error occurred: {0}")]
    Io(#[from] std::io::Error),
    #[error("An error occurred while encrypting/decrypting data: {0}")]
    Aes(#[from] aes_gcm::Error),
    #[error("An error occurred while serializing/deserializing data: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("An error occurred while trying to create a temporary file: {0}")]
    AsyncTemp(#[from] async_tempfile::Error),
}

impl ResponseError for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::UploadPointNotFound(_) => StatusCode::NOT_FOUND,
            Self::EmptyMetadata(_) | Self::EmptyFile(_) | Self::EmptyPathComponent => {
                StatusCode::BAD_REQUEST
            }
            Self::Io(_) | Self::Aes(_) | Self::Serde(_) | Self::Zip(_) | Self::AsyncTemp(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).body(self.to_string())
    }
}

#[derive(Debug, Parser)]
struct Options {
    #[cfg(debug_assertions)]
    #[clap(
        long,
        default_value = "localhost",
        help = "The host where the server will bind to"
    )]
    host: String,

    #[cfg(not(debug_assertions))]
    #[clap(
        long,
        default_value = "0.0.0.0",
        help = "The host where the server will bind to"
    )]
    host: String,

    #[clap(
        short,
        long,
        default_value_t = 8080,
        help = "The port where the server will bind to"
    )]
    port: u16,

    #[clap(short, long = "cert", help = "Optional path to the TLS certificate")]
    cert_path: Option<PathBuf>,

    #[clap(short, long = "key", help = "Optional path to the TLS private key")]
    key_path: Option<PathBuf>,
}

#[derive(Debug)]
struct AppState {
    storage_dir: PathBuf,
}

impl AppState {
    fn crypto_key_info_path(&self, uuid: Uuid) -> PathBuf {
        self.storage_dir.join(format!("{uuid}.crypto.json"))
    }

    fn upload_metadata_path(&self, uuid: Uuid) -> PathBuf {
        self.storage_dir.join(format!("{uuid}.metadata.json"))
    }

    pub async fn read_crypto_key_info(&self, uuid: Uuid) -> Result<CryptoKeyInfo, Error> {
        let crypto_info_path = self.crypto_key_info_path(uuid);
        let crypto_info = tokio::fs::read(&crypto_info_path).await?;
        let crypto_info = serde_json::from_slice::<CryptoKeyInfo>(&crypto_info)?;

        Ok(crypto_info)
    }

    pub async fn write_crypto_key_info(
        &self,
        uuid: Uuid,
        crypto_info: CryptoKeyInfo,
    ) -> Result<(), Error> {
        let crypto_info_path = self.crypto_key_info_path(uuid);
        let crypt = serde_json::to_string(&crypto_info)?;
        tokio::fs::write(&crypto_info_path, crypt).await?;
        Ok(())
    }

    pub async fn read_upload_metadata(&self, uuid: Uuid) -> Result<UploadMetadata, Error> {
        let meta_path = self.upload_metadata_path(uuid);
        let meta = tokio::fs::read(&meta_path).await?;
        let meta = serde_json::from_slice::<UploadMetadata>(&meta)?;
        Ok(meta)
    }

    pub async fn write_upload_metadata(
        &self,
        uuid: Uuid,
        metadata: UploadMetadata,
    ) -> Result<(), Error> {
        let meta_path = self.upload_metadata_path(uuid);
        let meta = serde_json::to_string(&metadata)?;
        tokio::fs::write(&meta_path, meta).await?;
        Ok(())
    }
}

#[derive(Serialize)]
struct UploadResponse {
    uuid: Uuid,
}

#[derive(Deserialize)]
struct FileMetadata {
    path: String,
}

#[derive(MultipartForm)]
#[multipart(deny_unknown_fields, duplicate_field = "deny")]
struct UploadForm {
    #[multipart(rename = "metadata[]")]
    metadata: Vec<MpJson<FileMetadata>>,
    #[multipart(rename = "file[]")]
    files: Vec<TempFile>,
}

async fn hash_path_contents<P: AsRef<Path>>(path: P) -> std::io::Result<String> {
    let file = File::open(path).await?;
    let mut stream = tokio_util::io::ReaderStream::new(file);

    let mut hasher = sha2::Sha256::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        hasher.update(chunk);
    }

    let res = hasher.finalize();

    Ok(format!("{res:x}"))
}

async fn encrypt_path_contents_and_write_to_dest<P: AsRef<Path>>(
    source: P,
    dest: P,
    crypto_pair: &CryptoPair,
) -> Result<(), Error> {
    let mut buffer = [0u8; MAX_STREAM_CHUNK_SIZE];
    let source = File::open(source).await?;
    let mut reader = BufReader::new(source);
    let mut dest = File::create(dest).await?;

    loop {
        let bytes_read = reader.read(&mut buffer).await?;
        if bytes_read == 0 {
            break;
        }

        let encrypted = crypto_pair
            .cipher
            .encrypt(&crypto_pair.nonce, &buffer[..bytes_read])?;

        let len = (encrypted.len() as u32).to_be_bytes();
        dest.write_all(&len).await?;
        dest.write_all(&encrypted).await?;
    }

    Ok(())
}

#[derive(Serialize, Deserialize, Default)]
struct UploadMetadata {
    path_to_original_size: HashMap<String, usize>,
}

#[derive(Serialize, Deserialize, Clone)]
struct CryptoKeyInfo {
    key: String,
    nonce: String,
}

#[derive(Clone)]
struct CryptoPair {
    cipher: AesGcm<Aes256, U12>,
    nonce: Nonce<<Aes256Gcm as AeadCore>::NonceSize>,
}

impl CryptoKeyInfo {
    pub fn generate() -> Self {
        let key = Aes256Gcm::generate_key(OsRng);
        let nonce = Aes256Gcm::generate_nonce(OsRng);
        Self {
            key: BASE64_STANDARD.encode(key),
            nonce: BASE64_STANDARD.encode(nonce),
        }
    }

    pub fn into_crypto_pair(self) -> CryptoPair {
        let key = BASE64_STANDARD
            .decode(self.key)
            .expect("Could not decode encryption key");

        let nonce = BASE64_STANDARD
            .decode(self.nonce)
            .expect("Could not decode nonce");

        let key = Key::<Aes256Gcm>::from_slice(key.as_slice());
        let nonce = Nonce::from_slice(nonce.as_slice());

        CryptoPair {
            cipher: Aes256Gcm::new(key),
            nonce: *nonce,
        }
    }
}

/// Endpoint to upload files. Returns the uuid of the upload point
#[post("/upload")]
async fn upload_files(
    MultipartForm(form): MultipartForm<UploadForm>,
    state: web::Data<AppState>,
) -> Result<impl Responder, Error> {
    // Validate form data
    for (file, meta) in form.files.iter().zip(form.metadata.iter()) {
        if file.size == 0 {
            let filename = file.file_name.as_ref().unwrap().to_string();
            return Err(Error::EmptyFile(filename));
        }

        if meta.path.is_empty() {
            let filename = file.file_name.as_ref().unwrap().to_string();
            return Err(Error::EmptyMetadata(filename));
        }
    }

    // Create new upload directory with unique ID
    let uuid = Uuid::new_v4();

    let upload_dir = state.storage_dir.join(uuid.to_string());

    tokio::fs::create_dir(&upload_dir).await?;

    // Generate crypto keys
    let crypto_info = CryptoKeyInfo::generate();

    let crypto_pair = crypto_info.clone().into_crypto_pair();

    let mut upload_meta = UploadMetadata::default();

    // Create destination paths and copy files to destination while encrypting
    for (file, meta) in form.files.iter().zip(form.metadata.iter()) {
        let dest = upload_dir.join(meta.path.trim_start_matches('/'));
        // Safety: We know that we have a parent
        let parent = dest.parent().unwrap();

        tokio::fs::create_dir_all(parent).await?;

        encrypt_path_contents_and_write_to_dest(file.file.path(), &dest, &crypto_pair).await?;

        upload_meta
            .path_to_original_size
            .insert(meta.path.clone(), file.size);
    }

    // Files have been moved. Save crypto and metadata files.
    state.write_crypto_key_info(uuid, crypto_info).await?;
    state.write_upload_metadata(uuid, upload_meta).await?;

    Ok(HttpResponse::Created().json(UploadResponse { uuid }))
}

#[derive(Serialize)]
struct FileEntry {
    name: String,
    path: String,
    size: u64,
}

#[derive(Serialize)]
struct DirEntry {
    name: String,
    path: String,
    entries: Vec<FileListing>,
}

#[derive(Serialize, Template)]
#[template(path = "file_listing.html", escape = "none")]
enum FileListing {
    File(FileEntry),
    Directory(DirEntry),
}

#[derive(Serialize, Template, WebTemplate)]
#[template(path = "file_listings.html", escape = "none")]
struct FileListings<'l> {
    entries: &'l [FileListing],
}

/// Endpoint to retrieve all files uploaded for that upload point
#[get("/{uuid}")]
async fn list_files(
    uuid: web::Path<Uuid>,
    state: web::Data<AppState>,
) -> Result<impl Responder, Error> {
    async fn get_files_recursively(
        upload_root: &Path,
        root: &Path,
        upload_meta: &UploadMetadata,
        acc: &mut Vec<FileListing>,
    ) -> Result<(), Error> {
        let mut reader = tokio::fs::read_dir(root).await?;
        while let Some(entry) = reader.next_entry().await? {
            let file_type = entry.file_type().await?;
            if file_type.is_file() {
                let as_path = entry.path();

                let path = as_path
                    .strip_prefix(upload_root)
                    .unwrap()
                    .to_string_lossy()
                    .to_string();

                let name = as_path.file_name().unwrap().to_string_lossy().into_owned();

                let size = upload_meta.path_to_original_size[&path] as u64;

                let listing = FileListing::File(FileEntry { name, path, size });

                acc.push(listing);
            } else if file_type.is_dir() {
                let mut dir_acc = Vec::new();
                let as_path = entry.path();

                Box::pin(get_files_recursively(
                    upload_root,
                    &as_path,
                    upload_meta,
                    &mut dir_acc,
                ))
                .await?;

                let path = as_path
                    .strip_prefix(upload_root)
                    .unwrap()
                    .to_string_lossy()
                    .to_string();

                let name = as_path.file_name().unwrap().to_string_lossy().into_owned();

                acc.push(FileListing::Directory(DirEntry {
                    path,
                    name,
                    entries: dir_acc,
                }))
            }
        }

        Ok(())
    }

    let upload_dir = state.storage_dir.join(uuid.to_string());
    if !tokio::fs::try_exists(&upload_dir).await? {
        return Err(Error::UploadPointNotFound(*uuid));
    }

    let upload_meta = state.read_upload_metadata(*uuid).await?;

    let mut files = Vec::new();
    get_files_recursively(&upload_dir, &upload_dir, &upload_meta, &mut files).await?;

    let template = FileListings { entries: &files };
    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(template.render().unwrap()))
}

#[derive(Deserialize)]
struct FileEndpointParams {
    pub uuid: Uuid,
    pub path: PathBuf,
}

#[get("/{uuid}/file/{path:.*}")]
async fn download_file(
    params: web::Path<FileEndpointParams>,
    state: web::Data<AppState>,
) -> Result<impl Responder, Error> {
    if params.path.components().count() == 0 {
        return Err(Error::EmptyPathComponent);
    }

    let upload_dir = state.storage_dir.join(params.uuid.to_string());
    if !tokio::fs::try_exists(&upload_dir).await? {
        return Err(Error::UploadPointNotFound(params.uuid));
    }

    let crypto_info = state.read_crypto_key_info(params.uuid).await?;
    let crypto_pair = crypto_info.into_crypto_pair();

    let file_path = upload_dir.join(&params.path);
    let file = File::open(&file_path).await?;

    let stream = async_stream::stream! {
        let mut reader = BufReader::new(file);

        loop {
            let mut len_buffer = [0u8; 4];
            let bytes_read = match reader.read_exact(&mut len_buffer).await {
                Ok(len) => len,
                Err(_)  => break,
            };

            if bytes_read == 0 {
                break;
            }

            let len = u32::from_be_bytes(len_buffer);

            let mut chunk = vec![0u8; len as usize];
            let bytes_read = match reader.read_exact(&mut chunk).await {
                Ok(bytes) => bytes,
                Err(_)  => break,
            };

            if bytes_read == 0 {
                break;
            }

            let decrypted = crypto_pair
                .cipher
                .decrypt(&crypto_pair.nonce, &chunk[..])?;

            yield Ok::<_, Error>(Bytes::from(decrypted));
        };
    };

    Ok(HttpResponse::Ok()
        .content_type(ContentType::plaintext())
        .insert_header(ContentDisposition::attachment(
            file_path.file_name().unwrap().to_string_lossy(),
        ))
        .streaming(stream))
}

#[get("/{uuid}/download-all")]
async fn download_all_files(
    uuid: web::Path<Uuid>,
    state: web::Data<AppState>,
) -> Result<impl Responder, Error> {
    async fn decrypt_and_compress_file<P: AsRef<Path>>(
        upload_root: P,
        path: P,
        crypto_pair: &CryptoPair,
        zip_writer: &mut ZipFileWriter<File>,
    ) -> Result<(), Error> {
        let path = path.as_ref();
        let zip_path = path
            .strip_prefix(upload_root)
            .unwrap()
            .to_string_lossy()
            .to_string();

        let entry = ZipEntryBuilder::new(zip_path.into(), Compression::Deflate);
        let mut entry_writer = zip_writer.write_entry_stream(entry).await?.compat_write();

        let file = File::open(path).await?;

        let mut reader = BufReader::new(file);

        loop {
            let mut len_buffer = [0u8; 4];
            let bytes_read = match reader.read_exact(&mut len_buffer).await {
                Ok(len) => len,
                Err(_) => break,
            };
            if bytes_read == 0 {
                break;
            }

            let len = u32::from_be_bytes(len_buffer);

            let mut chunk = vec![0u8; len as usize];
            let bytes_read = match reader.read_exact(&mut chunk).await {
                Ok(bytes) => bytes,
                Err(_) => break,
            };
            if bytes_read == 0 {
                break;
            }

            let decrypted = crypto_pair.cipher.decrypt(&crypto_pair.nonce, &chunk[..])?;

            entry_writer.write_all(&decrypted).await?;
        }

        entry_writer.into_inner().close().await?;

        Ok(())
    }

    async fn decrypt_and_compress_files_recursively(
        upload_root: &Path,
        root: &Path,
        crypto_pair: &CryptoPair,
        zip_writer: &mut ZipFileWriter<File>,
    ) -> Result<(), Error> {
        let mut reader = tokio::fs::read_dir(root).await?;
        while let Some(entry) = reader.next_entry().await? {
            let file_type = entry.file_type().await?;
            if file_type.is_file() {
                decrypt_and_compress_file(upload_root, &entry.path(), crypto_pair, zip_writer)
                    .await?;
            } else if file_type.is_dir() {
                Box::pin(decrypt_and_compress_files_recursively(
                    upload_root,
                    &entry.path(),
                    crypto_pair,
                    zip_writer,
                ))
                .await?;
            }
        }

        Ok(())
    }

    let upload_dir = state.storage_dir.join(uuid.to_string());
    if !tokio::fs::try_exists(&upload_dir).await? {
        return Err(Error::UploadPointNotFound(*uuid));
    }

    let crypto_info = state.read_crypto_key_info(*uuid).await?;
    let crypto_pair = crypto_info.into_crypto_pair();

    let temp_dir = async_tempfile::TempDir::new().await?;
    let zip_file_path = temp_dir.join(format!("{uuid}.zip"));
    let zip_file = File::create(&zip_file_path).await?;

    let mut writer = ZipFileWriter::with_tokio(zip_file);
    decrypt_and_compress_files_recursively(&upload_dir, &upload_dir, &crypto_pair, &mut writer)
        .await?;

    writer.close().await?;

    let file = File::open(&zip_file_path).await?;

    let stream = tokio_util::io::ReaderStream::new(file);
    Ok(HttpResponse::Ok()
        .content_type(ContentType::plaintext())
        .insert_header(ContentDisposition::attachment(
            zip_file_path.file_name().unwrap().to_string_lossy(),
        ))
        .streaming(stream))
}

#[derive(Serialize)]
struct FileSha {
    pub path: String,
    pub sha: String,
}

#[get("/{uuid}/sha/{path:.*}")]
async fn get_file_sha(
    params: web::Path<FileEndpointParams>,
    state: web::Data<AppState>,
) -> Result<impl Responder, Error> {
    if params.path.components().count() == 0 {
        return Err(Error::EmptyPathComponent);
    }

    let upload_dir = state.storage_dir.join(params.uuid.to_string());
    if !tokio::fs::try_exists(&upload_dir).await? {
        return Err(Error::UploadPointNotFound(params.uuid));
    }

    let file_path = upload_dir.join(&params.path);
    let sha = hash_path_contents(&file_path).await?;

    let res = FileSha {
        path: params.path.to_string_lossy().into_owned(),
        sha,
    };

    Ok(HttpResponse::Ok().json(res))
}

#[derive(Template, WebTemplate)]
#[template(path = "index.html")]
struct Index;

#[get("/")]
async fn index() -> impl Responder {
    Index
}

#[derive(Debug, Error)]
enum TlsConfigError {
    #[error(transparent)]
    PemError(#[from] pem::Error),

    #[error(transparent)]
    Rustls(#[from] rustls::Error),
}

fn load_rustls_config(cert_path: &Path, key_path: &Path) -> Result<ServerConfig, TlsConfigError> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();

    let cert_chain = CertificateDer::pem_file_iter(cert_path)?
        .flatten()
        .collect();

    let key_der = PrivateKeyDer::from_pem_file(key_path)?;

    let res = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)?;

    Ok(res)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let options = Options::parse();

    env_logger::Builder::from_env(Env::default().default_filter_or("warn")).init();

    match (options.cert_path.as_ref(), options.key_path.as_ref()) {
        (Some(_), None) => {
            error!("You specified a path to the TLS cert file but not one for the key file");
            std::process::exit(1);
        }
        (None, Some(_)) => {
            error!("You specified a path to the TLS key file but not one for the cert file");

            std::process::exit(1);
        }
        _ => {}
    };

    let mut storage_dir = match dirs::home_dir() {
        Some(home) => home,
        None => {
            error!("Could not determine the home directory");
            std::process::exit(1);
        }
    };

    storage_dir.push(".exchange-server/storage");

    tokio::fs::create_dir_all(&storage_dir).await?;

    let app_state = web::Data::new(AppState { storage_dir });

    let mut server = HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .send_wildcard()
            .allowed_methods(["POST", "OPTIONS"])
            .allowed_header(CONTENT_TYPE);

        App::new()
            .app_data(app_state.clone())
            .app_data(
                MultipartFormConfig::default()
                    .memory_limit(MAX_MEMORY_UPLOAD_SIZE)
                    .total_limit(MAX_UPLOAD_SIZE),
            )
            .wrap(Logger::default())
            .wrap(cors)
            .service(upload_files)
            .service(download_file)
            .service(download_all_files)
            .service(list_files)
            .service(get_file_sha)
            .service(index)
    });

    server = match (options.cert_path.as_ref(), options.key_path.as_ref()) {
        (Some(cert), Some(key)) => {
            let config = match load_rustls_config(cert, key) {
                Ok(config) => config,
                Err(e) => {
                    error!("Could not load TLS configuration. Reason: {e}");
                    std::process::exit(1);
                }
            };

            server.bind_rustls_0_23((options.host, options.port), config)?
        }
        _ => {
            warn!(
                "You didn't provide paths to the TLS cert and key files. This means the server will run in http mode!"
            );
            server.bind((options.host, options.port))?
        }
    };

    server.run().await
}
