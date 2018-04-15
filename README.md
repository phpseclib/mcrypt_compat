# mcrypt_compat

[![Build Status](https://travis-ci.org/phpseclib/mcrypt_compat.svg?branch=master)](https://travis-ci.org/phpseclib/mcrypt_compat)

PHP 5.x/7.x polyfill for mcrypt extension.

## Installation

With [Composer](https://getcomposer.org/):

```
composer require phpseclib/mcrypt_compat
```

## Supported algorithms

- rijndael-128
- rijndael-192
- rijndael-256
- des
- blowfish
- rc2
- tripledes
- arcfour

## Unsupported algorithms

- cast-128
- gost
- cast-256
- loki97
- saferplus
- wake
- blowfish-compat
- serpent
- xtea
- enigma

## Supported modes

- cbc
- ncfb
- cfb
- ctr
- ecb
- nofb
- stream

Although `nofb` is supported `ofb` is not. Further, mcrypt_compat's `ncfb` implementation has some incompatibles with mcrypt's implementation where `mcrypt_generic` and `mdecrypt_generic` are concerned. The unit tests elaborate.
