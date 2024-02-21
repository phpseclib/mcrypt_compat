<?php

/** @var iterable<SplFileInfo> $files */
$files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(__DIR__));
foreach ($files as $file) {
    if ($file->getExtension() === 'php' && $file->getPathname() !== __FILE__) {
        $fileContents = file_get_contents($file->getPathname());
        if ($fileContents === false) {
            throw new \RuntimeException('file_get_contents() failed: ' . $file->getPathname());
        }
        $patternToReplacementMap = array(
            '~(n assertIsArray\([^,\)]*,)([^,\)]*\))~' => '$1 string $2: void',
            '~(n assertIsArray\([^,\)]*\))~' => '$1: void',
            '~(n assertIsString\([^\)]*\))~' => '$1: void',
            '~(n assertStringContainsString\([^\)]*\))~' => '$1: void'
        );
        $updatedFileContents = preg_replace(
            array_keys($patternToReplacementMap),
            array_values($patternToReplacementMap),
            $fileContents
        );
        if (file_put_contents($file->getPathname(), $updatedFileContents) === false) {
            throw new \RuntimeException('file_put_contents() failed: ' . $file->getPathname());
        }
    }
}