# mcrypt_compat

[![CI Status](https://github.com/phpseclib/mcrypt_compat/actions/workflows/ci.yml/badge.svg?branch=1.0&event=push "CI Status")](https://github.com/phpseclib/mcrypt_compat/actions/workflows/ci.yml?query=branch%3A1.0)

PHP 5.x-8.x polyfill for mcrypt extension.

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
- ofb
- stream

mcrypt_compat's `ncfb` implementation has some incompatibles with mcrypt's implementation where `mcrypt_generic` and `mdecrypt_generic` are concerned. The unit tests elaborate.

## Emulating older PHP versions

The mcrypt extension's behavior underwent changes as new versions of PHP were released. By default mcrypt_compat emulates the behavior of PHP 7.1 but if you need to emulate how mcrypt behaved in, say, PHP 5.3.0, you may do so by doing `define('PHPSECLIB_MCRYPT_TARGET_VERSION', '5.3.0');` before including vendor/autoload.php (if you're using this with Composer).