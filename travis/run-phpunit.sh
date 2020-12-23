#!/bin/sh
set -e
set -x

PHPUNIT="$(dirname "$0")/../vendor/bin/phpunit"

if $PHPUNIT --atleast-version 9
then
    find tests -type f -name "*.php" -print0 | xargs -0 sed -i 's/\(n assertIsArray([^)]*)\)/\1: void/g'
    find tests -type f -name "*.php" -print0 | xargs -0 sed -i 's/\(n assertIsString([^)]*)\)/\1: void/g'
    find tests -type f -name "*.php" -print0 | xargs -0 sed -i 's/\(n assertStringContainsString([^)]*)\)/\1: void/g'
fi

"$PHPUNIT" -d error_reporting=24575 --coverage-clover=coverage.xml