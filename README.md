# secsipidx #

Secure SIP/Telephony Identity Extensions

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

### Use Cases ###

#### Generate Full Identity Header ####

A call from +493044448888 to +493055559999 with attestation level `A`, when the public key can be downloaded from `http://asipto.lab/stir/cert.pem`:

```
secsipidx -sign-full -orig-tn 493044448888 -dest-tn 493055559999 -attest A -x5u http://asipto.lab/stir/cert.pem -k ec256-private.pem
```

#### Check Full Identity Header ####

Check the identity header stored in file `identity.txt` using the public key in file `ec256-public.pem` with token expire of 3600 seconds

```
secsipidx -check -fidentity identity.txt -fpubkey ec256-public.pem -expire 3600
```

#### HTTP Server ####

Run `secsipidx` as an HTTP server listening on port `8090` for checking SIP identity with public key from file `ec256-public.pem`:

```
secsipidx -httpsrv ":8090" -httpdrv /secsipidx/http/public -fprvkey ec256-private.pem -fpubkey ec256-public.pem -expire 3600 -timeout 5
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

If OrigID is missing, then a UUID value is generated internally.

Example to get the Identity header value:

```
curl --data '493044442222,493088886666,A,,https://asipto.lab/v1/pub/cert.pem' http://127.0.0.1:8090/v1/sign-csv
```

##### HTTP File Server #####

When started with parameter `-httpdir`, the `secsipidx` servers the files from the respective
directory on the URL path `/v1/pub/`.

## C API ##

The code to get the C library is located in the `csecsipid` directory.

To generate the .h and static library files, run inside the directory:

```
make liba
```

Then the `*.h` and `libsecsipid.a` files can be copied to the folder where it is
wanted to be used.

The library is used by `secsipid` module of Kamailio SIP Server (https://www.kamailio.org):

  * https://www.kamailio.org/docs/modules/devel/modules/secsipid.html

## To-Do ##

  * documentation for C API functions
  * run as secure HTTPS server
  * internal cache of downloaded public keys used to verify Identity signatures

## Copyright ##

License: GPLv2

Copyright: © 2020 asipto.com

## Contributing ##

Bug reports and requests for new features have to be filled to:

  * https://github.com/asipto/secsipidx/issues

Code contributions have to be made via pull requests at:

  * https://github.com/asipto/secsipidx/pulls

The code of the pull requests is considered to be licensed under BSD license, unless explicitly requested to be a different license and agreed by the developers before merging.