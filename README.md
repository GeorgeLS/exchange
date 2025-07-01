# Exchange

## Overview

I've found myself many times wanting to share some files with friends or even myself.\
In that case, what we usually do is use either Messenger or GMail as a quick solution.

However, apart from the fact that I might now want my files to be uploaded in one of the aforementioned\
product servers, these solutions appear to be restricting in what types of files and sizes you can upload.

For that reason, I thought that it would be fun to create my own upload server for that purpose which I can self-host.\
This is what this _project_ is about.

This is a single/minimal upload/download server that requires no setup (apart from TLS configuration) that also uses\
Server Side Rendering in order to provide a frontend interface. I'm really bad at frontend development so please take\
that with a grain of salt. I might do a native client implementation in the future.

## Building the server

You can directly build this server by cloning this repository and running

```shell
cargo build --release
```

but what you probably want in order to have an easy deployment is the following steps:

```shell
cd exchange-server
./build-linux-amd64-static.sh
```

This requires that you have `docker` installed in your machine.
This script will use the `Dockerfile` in the `exchange-server` directory to build a static version of the server\
and put it under `exchange-server/build` folder.

## Running the server

The server supports the following command line options:

- `--host`: The host where the server will bind/listen to. By default, this `localhost` for debug builds and `0.0.0.0`
  for release builds
- `-p/--port`: The port where the server will bind/listen to. By default, this is `8080`
- `-c/--cert`: The path to the TLS certificate
- `-k/--key`: The path to the TLS private key

If you don't provide TLS configuration, the server will run in `http` mode and a warning will be printed stating so.

By default, the server will log to stdout messages up to `WARN` level. You can control the logging level using
`RUST_LOG`\
environment variable.

## Usage

The server is extremely simple to use and doesn't require any account creation by the users.\
The flow is the following:

1. Go to the index page. There, you can upload your files
2. Once the files are uploaded, the page will give you a unique URL which you can share with the person(s) that you want
   to share the files with
3. Visiting that URL, you can download individual files or all files at once (a ZIP archive will be downloaded in the
   latter case)

All the uploaded files are encrypted when uploaded and decrypted when downloading.

## "TODOs"

Couple of things that I would like to consider for the future:

- Automatic deletion of the files after downloading once or after `N` times or maybe some expiration period
- Ability to upload/download whole folders at once using the Web UI
- Native client implementations for interacting with the server
