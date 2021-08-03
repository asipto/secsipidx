# secsipidx #

Secure SIP/Telephony Identity Extensions.

Last Version: 1.1.0
Release: Jan 11, 2021

## Overview ##

Applications and libraries implementing STIR and SHAKEN (RFC8224, RFC8588),
used in SIP/VoIP services:

  * RFC8224 - https://tools.ietf.org/html/rfc8224
  * RFC8588 - https://tools.ietf.org/html/rfc8588

Components:

  * `secsipid`: Go library - common functions
  * `csecsipid`: C library - wrapper code to build dynamic or static library and .h include files
  * `secsipidx`: `main.go` - CLI tool and HTTP API server for checking or building SIP identity

## secsipidx ##

### Installation ###

Install Go language (golang), guidelines at:

  * https://golang.org
  * https://golang.org/doc/install

**Note**: When using Go version 1.16 or later, it's necessary to set the environment variable `GO111MODULE` to `off` prior to executing the `go get` or `make` commands below. When using an `sh`-compatible shell, this can be accomplished with `export GO111MODULE=off`

***

Deploy the `secsipidx` tool with:

```
go get github.com/asipto/secsipidx
```

The tool is located in `$GOPATH/bin/secsipidx`.

If you want to build and run locally:

```
go get -d github.com/asipto/secsipidx
cd $GOPATH/src/github.com/asipto/secsipidx/
go build

# run from local folder
# ./secsipidx ...
```

Install using the `make` command:

```
go get -d github.com/asipto/secsipidx
cd $GOPATH/src/github.com/asipto/secsipidx/
make
make install
```

The `secsipidx` tool is deployed to `/usr/local/bin/`. The `make install`
deploys also the libraries and `C` headers.

## Usage ##

To see the available command line options, run:

```
secsipidx -h
```

### Keys Generation ##

The `openssl` tool needs to be installed.

The following commands can be used to generate the private and public keys:

```
openssl ecparam -name prime256v1 -genkey -noout -out ec256-private.pem
openssl ec -in ec256-private.pem -pubout -out ec256-public.pem
```

### Usage ###

#### CLI - Generate Full Identity Header ####

A call from `+493044448888` to `+493055559999` with attestation level `A`, when the public key can be downloaded from `http://asipto.lab/stir/cert.pem`:

```
secsipidx -sign-full -orig-tn 493044448888 -dest-tn 493055559999 -attest A -x5u http://asipto.lab/stir/cert.pem -k ec256-private.pem
```

#### CLI - Check Full Identity Header ####

Check the identity header stored in file `identity.txt` using the public key in file `ec256-public.pem` with token expire of 3600 seconds

```
secsipidx -check -fidentity identity.txt -fpubkey ec256-public.pem -expire 3600
```

#### HTTP Server ####

Run `secsipidx` as an HTTP server listening on port `8090` for checking SIP identity with public key from file `ec256-public.pem`:

```
secsipidx -http-srv ":8090" -http-dir /secsipidx/http/public -fprvkey ec256-private.pem -fpubkey ec256-public.pem -expire 3600 -timeout 5
```
To run `secsipidx` as an HTTPS server on port `8093`, following command line parameters have to be provided:

```
secsipidx -https-srv ":8093" -https-pubkey /keys/secsipidx-public.key  -https-prvkey /keys/secsipidx-private.key ...
```

The TLS certificate (public and private keys) can be obtained from services like `Let's Encrypt` or use self-generated ones:

```
openssl genrsa -out secsipidx-private.key 2048
openssl ecparam -genkey -name secp384r1 -out secsipidx-private.key
openssl req -new -x509 -sha256 -key secsipidx-private.key -out secsipidx-public.key -days 365
```

##### Check Identity #####

If the identity header body is saved in the file `identity.txt`, the next command can be used to check it:

```
curl --data @identity.txt http://127.0.0.1:8090/v1/check
```

If `secsipidx` is started without `-fpubkey` or `-pubkey`, then the public key to check the signature
is downloaded from `x5u` URL (or the header `info` parameter). The value of `-timeout` parameter
is used to limit the download time of the public key via HTTP.

##### Generate Identity - CSV API #####

Prototype:

```
curl --data 'OrigTN,DestTN,ATTEST,OrigID,X5U' http://127.0.0.1:8090/v1/sign-csv
```

If `OrigID` is missing, then a `UUID` value is generated internally.

Example to get the `Identity` header value:

```
curl --data '493044442222,493088886666,A,,https://asipto.lab/v1/pub/cert.pem' http://127.0.0.1:8090/v1/sign-csv
```

##### HTTP File Server #####

When started with parameter `-httpdir`, the `secsipidx` servers the files from the respective
directory on the URL path `/v1/pub/`.

### Certificate Verification ###

The certificate retrieved from peers can be verified against system CAs or a list of
CAs stored in a file. The path to custom CAs files can be set via `--ca-file` and
`--ca-inter` parameters.

The verification mode can be set via `--cert-verify` parameter, which represents
an integer value build from the bit flags:

  * `1` (`1<<0`) - verify time validity (not expired and not before validity date)
  * `2` (`1<<1`) - verify against system root CAs
  * `4` (`1<<2`) - verify against custom root CAs in the file specified by `--ca-file`
  * `8` (`1<<3`) - verify against custom intermediate CAs in the file specified
  by `--ca-inter`
  * `16` (`1<<4`) - verify against certificate revocation list

The value can be combined, so `--cert-verify 7` means that the verification is
done against system room CAs and the custom CAs in the file specified by `--ca-file`,
together with time validity checks.

If `--cert-verify` is `0`, no verification is performed.

## Certificate Caching ##

There is support for a basic caching mechanism of the public keys in local files.

It can be activated by giving `-cache-dir /path/to/cachedir` cli parameter, how long the cached value is
considered valid can be controlled with `-cache-expire`.

The C library exports now:

```c
int SecSIPIDSetFileCacheOptions(char* dirPath, int expireVal);
```

which can be used to set the two values (the cache dir activates the caching mechanism).

The name of the file in the cache directory is created from URL replacing first `://` with `_` and
then the rest of `/` also with `_` -- I went this way instead of hashing (or encoding) the url to
be human readable. Last modified time of the file is used to determine when the value is considered expired.

Kamailio `secsipid` module was also enhanced with two new parameters to set the cache dir and expire values.

There is no locking/synchronization on accessing (read/write) cache files for the moment,
this can be done externally, for example with Kamailio by using `cfgutils` module:

```c
$var(url) = $(hdr(Identity){s.rmws}{param.value,info}{s.unbracket});
lock("$var(url)");
if(secsipid_check_identity("")) { ... }
unlock("$var(url)");
```

## C API ##

The code to get the `C` library is located in the `csecsipid` directory.

To generate the `.h` and static library files, run inside the directory:

```
make liba
```

Then the `*.h` and `libsecsipid.a` files can be copied to the folder where it is
wanted to be used.

The library is used by `secsipid` module of Kamailio SIP Server (https://www.kamailio.org):

  * https://www.kamailio.org/docs/modules/devel/modules/secsipid.html

The prototype of functions exported to `C` API and documentation are int the file:

  * https://github.com/asipto/secsipidx/blob/main/csecsipid/libsecsipid.h

### C Library Options ###

The library options that can be set with `SecSIPIDOptSetS()`, `SecSIPIDOptSetN()`
or `SecSIPIDOptSetV()`:

  * `CacheDirPath` (str) - the path to the folder where to store cached certificates
  that are downloaded from peers
  * `CacheExpires` (int) - number of seconds after which cached certificates are
  invalidated
  * `CertVerify` (int) - the certification verification mode, see the section
  `Certificate Verification` above
  * `CertCAFile` (str) - the path with the custom root CA certificates
  * `CertCAInter` (str) - the path with the custom intermediate CA certificates
  * `CertCRLFile` (str) - the path with the certificate revocation list

## To-Do ##

  * external cache (e.g., use of Redis) of downloaded public keys used to verify
  Identity signatures
  * blacklisting of unresponsive x5u URLs
  * support more data formats for HTTP API (e.g., JSON for generating Identity)
  * configuration file

## Copyright ##

License: `BSD 3-Clause Clear License`

Copyright: © 2020-2021 asipto.com

## Contributing ##

Bug reports and requests for new features have to be filled to:

  * https://github.com/asipto/secsipidx/issues

Code contributions have to be made via pull requests at:

  * https://github.com/asipto/secsipidx/pulls

The code of the pull requests is considered to be licensed under BSD license, unless explicitly requested to be a different license and agreed by the developers before merging.

## Testing ##

To test the secsipid library, `cd` into `secsipid/` and run:
```bash
go test -v
```

Some of the unit tests take multiple seconds because they're forcing a time out or
waiting for something to expire. These tests are skipped by default.

To run all tests, including these longer ones, set the environemnt variable: `GO_TEST_ALL` to `on`:
```bash
GO_TEST_ALL=on go test -v
```
