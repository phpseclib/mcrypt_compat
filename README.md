# mcrypt_compat

[![Build Status](https://travis-ci.org/terrafrost/mcrypt_compat.svg?branch=master)](https://travis-ci.org/terrafrost/random_compat)

PHP 5.x polyfill for mcrypt extension.

## Supported algorithms

- rijndael-128
- rijndael-192
- rijndael-256
- blowfish-compat
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
- serpent
- xtea
- enigma

## Supported modes

- cbc
- ncfb
- ctr
- ecb
- nofb
- stream

Although `ncfb` and `nofb` are supported `cfb` and `ofb` are not. Further, mcrypt_compat's `ncfb` implementation has some incompatibles with mcrypt's implementation where `mcrypt_generic` and `mdecrypt_generic` are concerned. The unit tests elaborate.