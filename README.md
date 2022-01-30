# mcrypt_compat

[![Build Status](https://travis-ci.org/phpseclib/mcrypt_compat.svg?branch=master)](https://app.travis-ci.com/github/phpseclib/mcrypt_compat)

PHP 5.x-8.x polyfill for mcrypt extension.

## Supporting mcrypt_compat

- [Become a backer or sponsor on Patreon](https://www.patreon.com/phpseclib)
- [One-time donation via PayPal or crypto-currencies](http://sourceforge.net/donate/index.php?group_id=198487)
- [Subscribe to Tidelift](https://tidelift.com/subscription/pkg/packagist-phpseclib-mcrypt-compat?utm_source=packagist-phpseclib-mcrypt-compat&utm_medium=referral&utm_campaign=readme)

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

## Security contact information

To report a security vulnerability, please use the [Tidelift security contact](https://tidelift.com/security). Tidelift will coordinate the fix and disclosure.