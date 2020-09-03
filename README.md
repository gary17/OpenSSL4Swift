# OpenSSL4Swift

## Purpose

This repository is meant as an educational resource on the subject of using software design patterns in iOS apps written in Swift.

## Problem

The iOS platform does not include direct support for the OpenSSL library.

## Solution

OpenSSL4Swift is a small, sample utility library based on Swift Manual Memory Management and C/Objective-C bridging that demonstrates using OpenSSL library functionality directly from Swift.

## WARNING

**Never use an untrusted, precompiled version of OpenSSL. Build your own.**

## Setup

### OpenSSL Setup

- download a source code -based distribution of OpenSSL directly from [openssl.org](https://www.openssl.org) and build it for iOS under macOS (for an example on how to do that, see [openssl-build.sh](https://gist.github.com/foozmeat/5154962))

- copy an OpenSSL distribution to an Xcode project folder, under `<project-dir>/OpenSSL`, side-by-side with `<project>.xcodeproj`

### Xcode Project Setup

- select `Build Settings` >> `Search Paths` >> `Header Search Paths`, enter a full path to the OpenSSL include file directory, e.g. `"$(PROJECT_DIR)/OpenSSL/include"` (with quotes)

- select `Build Phases` >> `Link Binary With Libraries` >> `+`, browse for `<project-dir>/OpenSSL/lib/libcrypto.a`

- select `Build Phases` >> `Link Binary With Libraries` >> `+`, browse for `<project-dir>/OpenSSL/lib/libssl.a`

### Bridging Header Setup

- select `File` >> `New` >> `File`

- select `iOS`, `Source`, `Objective-C File`

- name the new file `bridge.m` (or anything, really – it's a dummy source file that you'll delete right after Xcode generates bridging headers)

- select `Next`, `Create`

- select `Create Bridging Header` (will create `<project>-Bridging-Header.h` and `<project>Tests-Bridging-Header.h`, as well as add them to the project)

- delete `bridge.mm` from the project

- add OpenSSL C header files to the new `<project>-Bridging-Header.h` and `<project>Tests-Bridging-Header.h` bridging headers (for an example, see `OpenSSL4Swift-Bridging-Header.h`)

### OpenSSL Header File Patching

Some older versions of OpenSSL include an improperly formatted `<project-dir>/OpenSSL/include/openssl/rsa.h` header file. If you run into Xcode build problems, patch `BIGNUM *I` as `BIGNUM *i`:

	int (*rsa_mod_exp)(BIGNUM *r0,const BIGNUM *I,RSA *rsa,BN_CTX *ctx); /* Can be null */
	int (*rsa_mod_exp)(BIGNUM *r0,const BIGNUM *i,RSA *rsa,BN_CTX *ctx); /* Can be null */

## Components

|         | File | Purpose |
----------|------|----------
:octocat: | [OpenSSL4Swift.swift](OpenSSL4Swift/OpenSSL4Swift.swift) | a sample utility library that demonstrates using OpenSSL directly from Swift
:octocat: | [OpenSSL4SwiftTests.swift](OpenSSL4SwiftTests/OpenSSL4SwiftTests.swift) | a sample test suite with usage samples
:octocat: | [OpenSSL4Swift-Bridging-Header.h](OpenSSL4Swift-Bridging-Header.h) | a sample bridging header with a set of OpenSSL include files
