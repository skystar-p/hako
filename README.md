# Hako
Simple file sharing with client-side encryption, powered by Rust and WebAssembly  

![preview](./res/preview.png)
  
Not feature-packed, but basic functionalities are just working. Feature requests and PR are very welcome.

## Features
* Handy file sharing
* Handy text-snippet sharing
* Client-side encryption using `XChacha20Poly1305`
* Fast and safe implementations thanks to [Rust](https://www.rust-lang.org/)
* Neat Web UI built with WebAssembly
* Asynchronous upload, encryption, download, and decryption on your browser.

## Why?
Sharing file safely between two devices is quite annoying. Hardware mediums(like USB flash memory) can be useful, but sharing file between mobile devices or different operating systems are frustrating.
You can go with third-party file hosting server or E-mail, but those are not safe and not good for your privacy.  
Hako is web application, which gives you great compatibility among various devices and operating systems. Also, Hako uses client-side encryption, so no one can see your original file, even the Hako server.

## Build
For simplicity, Hako bundles frontend dist files into server binary statically. So you **MUST** build frontend web application first, and then build server application.

### Frontend
You need two additional tools: [`trunk`](https://trunkrs.dev/) and [`tailwindcss`](https://tailwindcss.com/).
```sh
# To install trunk, use:
cargo install --locked trunk

# To install tailwindcss, use:
yarn global add tailwindcss
```

And build your WASM application.
```sh
cd ./webapp
rm -rf dist
trunk build --release
```

### Server
You need `cargo` to build server. If you don't have it, follow the instructions in [here](https://www.rust-lang.org/tools/install).
```sh
cd ./server
cargo build --release
```
Hako uses simple SQLite database to store your encrypted files and metadata. So no external database setting is required, but you may give database file path by argument or environment variable. See [here](https://github.com/skystar-p/hako/blob/b8bed17019232452d8ca98ff9a0ae20521af02e1/server/src/config.rs#L9).


## Run
Serving Hako application is dead simple. No additional file-serving proxy needed. Just run your Hako server binary behind of HTTP proxy to take advantage of TLS.  
You can check configuration info by running:
```sh
./hako --help
```

## To-dos
* Authentication
    * WebAuthn
    * or just plain username-password pair
* File expiry, download limit
    * Or just LRU
* Performance gain using Web Worker
* CLI tool
    * WASM can provide compatibility among various environment, and CLI downloader will provide good performance
