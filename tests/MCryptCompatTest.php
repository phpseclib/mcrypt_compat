<?php

class MCryptCompatTest extends PHPUnit\Framework\TestCase
{
    public function testAlgorithmList()
    {
        $this->assertInternalType('array', phpseclib_mcrypt_list_algorithms());
    }

    public function testListAlgorithms()
    {
        $this->assertInternalType('array', phpseclib_mcrypt_list_algorithms());
    }

    public function testListsModes()
    {
        $this->assertInternalType('array', phpseclib_mcrypt_list_modes());
    }

    public function testMcryptCreateIv()
    {
        $expectedLen = 20;
        $result = phpseclib_mcrypt_create_iv($expectedLen);
        $this->assertInternalType('string', $result);
        $this->assertEquals($expectedLen, strlen($result));
    }

    public function testMcryptCreateIvException()
    {
        $this->setExpectedException('PHPUnit_Framework_Error_Warning');

        $result = phpseclib_mcrypt_create_iv(0);
    }

    public function testMcryptModuleOpenWithErrorModeException()
    {
        $this->setExpectedException('PHPUnit_Framework_Error_Warning');

        $result = phpseclib_mcrypt_module_open('arcfour', '', 'cbc', '');
    }
    
    /**
     * @dataProvider mcryptModuleNameProvider
     */
    public function testMcryptModuleOpen($moduleName, $cipherMode, $expectedInstance)
    {
        $resultInstance = phpseclib_mcrypt_module_open($moduleName, '', $cipherMode, '');
        $this->assertInstanceOf($expectedInstance, $resultInstance);
    }

    public function testMcryptModuleOpenException()
    {
        $this->setExpectedException('PHPUnit_Framework_Error_Warning');

        $result = phpseclib_mcrypt_module_open('unknown-module-name', '', 'cbc', '');
    }

    public function testMcryptModuleGetAlgoBlockSizeWithNumber()
    {
        $result = phpseclib_mcrypt_module_get_algo_block_size('arcfour');
        $this->assertEquals(-1, $result);
    }

    public function testMcryptEncGetBlockSize()
    {
        $td = phpseclib_mcrypt_module_open('blowfish', '', 'cbc', '');
        $expectedBlockLen = $td->getBlockLength() >> 3;
        $result = phpseclib_mcrypt_enc_get_block_size($td);
        $this->assertEquals($expectedBlockLen, $result);
    }

    public function testMcryptGetAlgoKeySizeBad()
    {
        $this->setExpectedException('PHPUnit_Framework_Error_Warning');

        phpseclib_mcrypt_module_get_algo_key_size('zzz');
    }

    public function testMcryptGetAlgoKeySizeGood()
    {
        $this->assertEquals(
            mcrypt_module_get_algo_key_size('rijndael-128'),
            phpseclib_mcrypt_module_get_algo_key_size('rijndael-128')
        );
    }

    public function testMcryptGetIVSizeBad()
    {
        $this->setExpectedException('PHPUnit_Framework_Error_Warning');

        phpseclib_mcrypt_get_iv_size('zzz', 'cbc');
    }

    public function testMcryptGetIVSizeGood()
    {
        if (!extension_loaded('mcrypt')) {
            $this->markTestSkipped('mcrypt must be installed to compare the output of the shim to the original mcrypt');
        }

        $this->assertEquals(
            mcrypt_get_iv_size('rijndael-128', 'cbc'),
            phpseclib_mcrypt_get_iv_size('rijndael-128', 'cbc')
        );
    }

    public function testMcryptGetKeySizeBad()
    {
        $this->setExpectedException('PHPUnit_Framework_Error_Warning');

        phpseclib_mcrypt_get_key_size('zzz', 'cbc');
    }

    public function testMcryptGetKeySizeGood()
    {
        if (!extension_loaded('mcrypt')) {
            $this->markTestSkipped('mcrypt must be installed to compare the output of the shim to the original mcrypt');
        }

        $this->assertEquals(
            mcrypt_get_key_size('rijndael-128', 'cbc'),
            phpseclib_mcrypt_get_key_size('rijndael-128', 'cbc')
        );
    }

    public function testMcryptGetBlockSizeBad()
    {
        $this->setExpectedException('PHPUnit_Framework_Error_Warning');

        phpseclib_mcrypt_get_block_size('zzz', 'cbc');
    }

    public function testMcryptGetBlockSizeGood()
    {
        if (!extension_loaded('mcrypt')) {
            $this->markTestSkipped('mcrypt must be installed to compare the output of the shim to the original mcrypt');
        }

        $this->assertEquals(
            mcrypt_get_block_size('rijndael-128', 'cbc'),
            phpseclib_mcrypt_get_block_size('rijndael-128', 'cbc')
        );
    }

    /**
     * @dataProvider mcryptEncGetAlgorithmsNameProvider
     */
    public function testMcryptEncGetAlgorithmsName($moduleName, $cipherMode, $expectedContainStr)
    {
        $td = phpseclib_mcrypt_module_open($moduleName, '', $cipherMode, '');
        $result = phpseclib_mcrypt_enc_get_algorithms_name($td);
        $this->assertContains($expectedContainStr, $result);
    }

    public function testMcryptEncGetModesName()
    {
        $td = phpseclib_mcrypt_module_open('blowfish', '', 'cbc', '');
        $result = phpseclib_mcrypt_enc_get_modes_name($td);
        $this->assertEquals('CBC', $result);
    }

    public function testMcryptEncIsBlockAlgorithmMode()
    {
        $td = phpseclib_mcrypt_module_open('blowfish', '', 'cbc', '');
        $result = phpseclib_mcrypt_enc_is_block_algorithm_mode($td);
        $this->assertTrue($result);
        
        $td = phpseclib_mcrypt_module_open('arcfour', '', 'stream', '');
        $result = phpseclib_mcrypt_enc_is_block_algorithm_mode($td);
        $this->assertFalse($result);
    }
    
    public function testMcryptEncIsBlockAlgorithm()
    {
        $td = phpseclib_mcrypt_module_open('blowfish', '', 'cbc', '');
        $result = phpseclib_mcrypt_enc_is_block_algorithm($td);
        $this->assertTrue($result);
        
        $td = phpseclib_mcrypt_module_open('arcfour', '', 'stream', '');
        $result = phpseclib_mcrypt_enc_is_block_algorithm($td);
        $this->assertFalse($result);
    }

    public function testMcryptEncIsBlockMode()
    {
        $td = phpseclib_mcrypt_module_open('blowfish', '', 'cbc', '');
        $result = phpseclib_mcrypt_enc_is_block_mode($td);
        $this->assertTrue($result);
        
        $td = phpseclib_mcrypt_module_open('blowfish', '', 'ecb', '');
        $result = phpseclib_mcrypt_enc_is_block_mode($td);
        $this->assertTrue($result);
        
        $td = phpseclib_mcrypt_module_open('arcfour', '', 'stream', '');
        $result = phpseclib_mcrypt_enc_is_block_mode($td);
        $this->assertFalse($result);
    }

    public function testMcryptEncSelfTest()
    {
        $td = phpseclib_mcrypt_module_open('blowfish', '', 'cbc', '');
        $result = phpseclib_mcrypt_enc_self_test($td);
        $this->assertTrue($result);
    }

    public function testMcryptGenericInitWithErrorIvSize()
    {
        $this->setExpectedException('PHPUnit_Framework_Error_Warning');

        $td = phpseclib_mcrypt_module_open('blowfish', '', 'cbc', '');
        $result = phpseclib_mcrypt_generic_init($td, 'key', 1);
    }

    public function testMcryptGenericInitWithErrorNullKeySize()
    {
        $this->setExpectedException('PHPUnit_Framework_Error_Warning');

        $td = phpseclib_mcrypt_module_open('blowfish', '', 'cbc', '');
        $ivSize = phpseclib_mcrypt_enc_get_iv_size($td);
        $ivStr = str_repeat('=', $ivSize);
        $result = phpseclib_mcrypt_generic_init($td, null, $ivStr);
    }

    public function testMcryptGenericInitWithErrorMaxKeySize()
    {
        $this->setExpectedException('PHPUnit_Framework_Error_Warning');

        $td = phpseclib_mcrypt_module_open('blowfish', '', 'cbc', '');
        $ivSize = phpseclib_mcrypt_enc_get_iv_size($td);
        $ivStr = str_repeat('=', $ivSize);
        $maxKeySize = phpseclib_mcrypt_enc_get_key_size($td);
        $maxKeySize += 1;
        $bigKeyStr = str_repeat('=', $maxKeySize);
        $result = phpseclib_mcrypt_generic_init($td, $bigKeyStr, $ivStr);
    }

    public function testMcryptGenericHelperWithException()
    {
        $this->setExpectedException('PHPUnit_Framework_Error_Warning');

        $data = 'data';
        $op = 'operation';
        $td = phpseclib_mcrypt_module_open('blowfish', '', 'cbc', '');
        unset($td->mcrypt_polyfill_init);
        $result = phpseclib_mcrypt_generic_helper($td, $data, $op);
    }

    public function testMcryptGenericDeinitWithException()
    {
        $this->setExpectedException('PHPUnit_Framework_Error_Warning');

        $td = phpseclib_mcrypt_module_open('blowfish', '', 'cbc', '');
        unset($td->mcrypt_polyfill_init);
        $result = phpseclib_mcrypt_generic_deinit($td);
    }

    public function testMcryptModuleClose()
    {
        $td = phpseclib_mcrypt_module_open('blowfish', '', 'cbc', '');
        $result = phpseclib_mcrypt_module_close($td);
        $this->assertTrue($result);
    }

    public function testMcryptModuleGetSupportedKeySizesWithDESAnd3DES()
    {
        $td = phpseclib_mcrypt_module_open('blowfish', '', 'cbc', '');
        $result = phpseclib_mcrypt_module_get_supported_key_sizes('des');
        $this->assertContains(8, $result);

        $result = phpseclib_mcrypt_module_get_supported_key_sizes('tripledes');
        $this->assertContains(24, $result);
    }

    public function testMcryptEncGetSupportedKeySizes()
    {
        $td = phpseclib_mcrypt_module_open('des', '', 'cbc', '');
        $result = phpseclib_mcrypt_enc_get_supported_key_sizes($td);
        $this->assertContains(8, $result);
    }

    /**
     * @dataProvider mcryptBlockModuleNameProvider
     */
    public function testMcryptModuleIsBlockAlgorithmMode($modeName, $expectedValue)
    {
        $result = phpseclib_mcrypt_module_is_block_algorithm_mode($modeName);
        $this->assertEquals($result, $expectedValue);
    }

    /**
     * @dataProvider mcryptBlockModuleAlgoNameProvider
     */
    public function testphpseclib_mcrypt_module_is_block_algorithm($algoName, $expectedValue)
    {
        $result = phpseclib_mcrypt_module_is_block_algorithm($algoName);
        $this->assertEquals($result, $expectedValue);
    }

    /**
     * @dataProvider mcryptModuleIsBlockModeProvider
     */
    public function testMcryptModuleIsBlockMode($modeName, $expectedValue)
    {
        $result = phpseclib_mcrypt_module_is_block_mode($modeName, $expectedValue);
        $this->assertEquals($result, $expectedValue);
    }

    public function testMcryptModuleSelfTest()
    {
        $result = phpseclib_mcrypt_module_self_test('blowfish');
        $this->assertTrue($result);

        $result = phpseclib_mcrypt_module_self_test('invalid-algorithm-name');
        $this->assertFalse($result);
    }

    public function testMcryptHelperWithInitialModuleException()
    {
        $this->setExpectedException('PHPUnit_Framework_Error_Warning');

        $result = phpseclib_mcrypt_helper('invalid-module', 'key', 'data', 'cbc', 'iv-str', 'operation');
    }

    public function testMcryptHelperWithKeySizeNotSupportedException()
    {
        $this->setExpectedException('PHPUnit_Framework_Error_Warning');

        $key = str_repeat('===', 50);
        $result = phpseclib_mcrypt_helper('blowfish', $key, '', 'cbc', '', '');
    }

    public function testMcryptHelperWithInitialIvSizeException()
    {
        $this->setExpectedException('PHPUnit_Framework_Error_Warning');

        $result = phpseclib_mcrypt_helper('blowfish', '', '', 'cbc', null, '');
    }

    public function testMcryptHelperWithReceiveInitialIvSizeException()
    {
        $this->setExpectedException('PHPUnit_Framework_Error_Warning');

        $result = phpseclib_mcrypt_helper('blowfish', 10, '', 'cbc', 'iv-str', '');
    }

    public function testMcryptFilterWithOnCreateStreamParamsMustBeArray()
    {
        $this->setExpectedException('PHPUnit_Framework_Error_Notice');

        $filter = new phpseclib_mcrypt_filter();
        $filter->onCreate();
    }

    public function testMcryptFilterWithOnCreateStreamParamsNotProvidedOrString()
    {
        $this->setExpectedException('PHPUnit_Framework_Error_Notice');

        $params = array('fake-key' => 'fake-value');
        $filter = new phpseclib_mcrypt_filter();
        $filter->params = $params;
        $filter->onCreate();
    }

    public function testMcryptFilterWithOnCreateStreamParamsNotKeyOrString()
    {
        $this->setExpectedException('PHPUnit_Framework_Error_Notice');

        $params = array('iv' => 'fake-iv-str');
        $filter = new phpseclib_mcrypt_filter();
        $filter->params = $params;
        $filter->onCreate();
    }

    public function testMcryptFilterWithOnCreateErrorOpenEncryptionModule()
    {
        $this->setExpectedException('PHPUnit_Framework_Error_Notice');

        $params = array('iv' => 'fake-iv-str', 'key' => 'fake-key');
        $filter = new phpseclib_mcrypt_filter();
        $filter->filtername = 'fake.filter.name';
        $filter->params = $params;
        $filter->onCreate();
    }

    public function testMcryptFilterWithOnCreateErrorCryptname()
    {
        $this->setExpectedException('PHPUnit_Framework_Error_Notice');

        $params = array('iv' => 'fake-iv-str', 'key' => 'fake-key');
        $filter = new phpseclib_mcrypt_filter();
        $filter->filtername = 'fake_crypt.fake_cipher';
        $filter->params = $params;
        $filter->onCreate();
    }

    public function testMcryptFilterWithOnCreateErrorCipherName()
    {
        $this->setExpectedException('PHPUnit_Framework_Error_Notice');

        $params = array('iv' => 'fake-iv-str', 'key' => 'fake-key');
        $filter = new phpseclib_mcrypt_filter();
        $filter->filtername = 'mcrypt.fake_cipher';
        $filter->params = $params;
        $filter->onCreate();
    }

    public function testAESBasicSuccess()
    {
        if (!extension_loaded('mcrypt')) {
            $this->markTestSkipped('mcrypt must be installed to compare the output of the shim to the original mcrypt');
        }

        $key = str_repeat('z', 16);
        $iv = str_repeat('z', 16);

        // a plaintext / ciphertext of length 1 is of an insufficient length for cbc mode
        $plaintext = str_repeat('a', 16);

        $mcrypt = mcrypt_encrypt('rijndael-128', $key, $plaintext, 'cbc', $iv);
        $compat = phpseclib_mcrypt_encrypt('rijndael-128', $key, $plaintext, 'cbc', $iv);
        $this->assertEquals(bin2hex($mcrypt), bin2hex($compat), 'zzz1');

        $ciphertext = $mcrypt;

        $mcrypt = mcrypt_decrypt('rijndael-128', $key, $ciphertext, 'cbc', $iv);
        $compat = phpseclib_mcrypt_decrypt('rijndael-128', $key, $ciphertext, 'cbc', $iv);
        $this->assertEquals($mcrypt, $compat, 'zzz2');

        $decrypted = $mcrypt;
        $this->assertEquals($plaintext, $decrypted, 'zzz3');
    }

    public function testAESDiffKeyLength()
    {
        if (!extension_loaded('mcrypt')) {
            $this->markTestSkipped('mcrypt must be installed to compare the output of the shim to the original mcrypt');
        }

        $key = str_repeat('z', 24);
        $iv = str_repeat('z', 16);

        // a plaintext / ciphertext of length 1 is of an insufficient length for cbc mode
        $plaintext = str_repeat('a', 16);

        $mcrypt = mcrypt_encrypt('rijndael-128', $key, $plaintext, 'cbc', $iv);
        $compat = phpseclib_mcrypt_encrypt('rijndael-128', $key, $plaintext, 'cbc', $iv);
        $this->assertEquals(bin2hex($mcrypt), bin2hex($compat));
    }

    public function testBadParamsMcrypt()
    {
        if (!extension_loaded('mcrypt')) {
            $this->markTestSkipped('mcrypt must be demonstrate it\'s behaviors');
        }

        $this->setExpectedException('PHPUnit_Framework_Error_Warning');

        mcrypt_encrypt('rijndael-128', 'abc', 'asdf', 'cbc', 'zz');
    }

    /**
     * pretty much the same thing as testBadParamsMcrypt
     */
    public function testBadParamsMcryptCompat()
    {
        $this->setExpectedException('PHPUnit_Framework_Error_Warning');

        phpseclib_mcrypt_encrypt('rijndael-128', 'abc', 'asdf', 'cbc', 'zz');
    }

    /**
     * in theory, in continuous mode, you ought to be able to encrypt / decrypt successive substring's of a
     * cipher/plain-text and get the same result as you would if you did the whole cipher/plain-text in one
     * go but with mcrypt you can't whereas with mcrypt_compat you can. imho this is a bug in mcrypt and it's
     * not behavior that mcrypt_compat emulates. testMcryptNCFB() and testPhpseclibNCFB() demonstrate
     */
    public function ncfbHelper($prefix)
    {
        $td = call_user_func($prefix . 'mcrypt_module_open', 'rijndael-128', '', 'ncfb', '');
        call_user_func($prefix . 'mcrypt_generic_init', $td, str_repeat('a', 16), str_repeat('a', 16));
        $blocks = array(10, 5, 17, 16);
        $v1 = $v2 = '';
        foreach ($blocks as $block) {
            $v1.= call_user_func($prefix . 'mdecrypt_generic', $td, str_repeat('c', $block));
            $v2.= str_repeat('c', $block);
        }
        call_user_func($prefix . 'mcrypt_generic_deinit', $td);
        call_user_func($prefix . 'mcrypt_generic_init', $td, str_repeat('a', 16), str_repeat('a', 16));
        $v2 = call_user_func($prefix . 'mdecrypt_generic', $td, $v2);

        return array($v1, $v2);
    }

    public function testMcryptNCFB()
    {
        if (!extension_loaded('mcrypt')) {
            $this->markTestSkipped('mcrypt must be demonstrate it\'s behaviors');
        }

        list($v1, $v2) = $this->ncfbHelper('');
        $this->assertNotSame($v1, $v2);
    }

    public function testPhpseclibNCFB()
    {
        list($v1, $v2) = $this->ncfbHelper('phpseclib_');
        $this->assertSame($v1, $v2);
    }

    /**
     * mcrypt and phpseclib 1.0/2.0 null-pad plaintext's and ciphertext's
     */
    public function testNullPadding()
    {
        if (!extension_loaded('mcrypt')) {
            $this->markTestSkipped('mcrypt must be installed to compare the output of the shim to the original mcrypt');
        }

        $key = str_repeat('z', 16);
        $iv = str_repeat('z', 16);

        // a plaintext / ciphertext of length 1 is of an insufficient length for cbc mode
        $plaintext = $ciphertext = 'a';

        $mcrypt = bin2hex(mcrypt_encrypt('rijndael-128', $key, $plaintext, 'cbc', $iv));
        $compat = bin2hex(phpseclib_mcrypt_encrypt('rijndael-128', $key, $plaintext, 'cbc', $iv));
        $this->assertEquals($mcrypt, $compat);

        $mcrypt = bin2hex(mcrypt_decrypt('rijndael-128', $key, $ciphertext, 'cbc', $iv));
        $compat = bin2hex(phpseclib_mcrypt_decrypt('rijndael-128', $key, $ciphertext, 'cbc', $iv));
        $this->assertEquals($mcrypt, $compat);
    }

    /**
     * valid AES key lengths are 128, 192 and 256-bit. if you pass in, say, a 160-bit key (20 bytes)
     * both phpseclib 1.0/2.0 and mcrypt will null pad 192-bits. at least with mcrypt_generic().
     */
    public function testMiddleKey()
    {
        if (!extension_loaded('mcrypt')) {
            $this->markTestSkipped('mcrypt must be installed to compare the output of the shim to the original mcrypt');
        }

        $key = str_repeat('z', 20);
        $iv = str_repeat('z', 16);

        $plaintext = 'a';

        $td = mcrypt_module_open('rijndael-128', '', 'cbc', '');
        mcrypt_generic_init($td, $key, $iv);
        $mcrypt = bin2hex(mcrypt_generic($td, 'This is very important data'));

        $td = phpseclib_mcrypt_module_open('rijndael-128', '', 'cbc', '');
        phpseclib_mcrypt_generic_init($td, $key, $iv);
        $phpseclib = bin2hex(phpseclib_mcrypt_generic($td, 'This is very important data'));

        $this->assertEquals($mcrypt, $phpseclib);
    }

    /**
     * although mcrypt_generic() null pads keys mcrypt_encrypt() does not
     *
     * @requires PHP 5.6
     */
    public function testMiddleKey2()
    {
        if (!extension_loaded('mcrypt')) {
            $this->markTestSkipped('mcrypt must be demonstrate it\'s behaviors');
        }

        $this->setExpectedException('PHPUnit_Framework_Error_Warning');

        $key = str_repeat('z', 20);
        $iv = str_repeat('z', 16);

        $plaintext = 'a';

        mcrypt_encrypt('rijndael-128', $key, $plaintext, 'cbc', $iv);
    }

    /**
     * phpseclib_mcrypt_generic() behaves in the same way
     */
    public function testMiddleKey3()
    {
        $this->setExpectedException('PHPUnit_Framework_Error_Warning');

        $key = str_repeat('z', 20);
        $iv = str_repeat('z', 16);

        $plaintext = 'a';

        phpseclib_mcrypt_encrypt('rijndael-128', $key, $plaintext, 'cbc', $iv);
    }

    public function testShortKey()
    {
        if (!extension_loaded('mcrypt')) {
            $this->markTestSkipped('mcrypt must be installed to compare the output of the shim to the original mcrypt');
        }

        $key = str_repeat('z', 4);
        $iv = str_repeat('z', 16);

        $plaintext = 'a';

        $td = mcrypt_module_open('rijndael-128', '', 'cbc', '');
        mcrypt_generic_init($td, $key, $iv);
        $mcrypt = bin2hex(mcrypt_generic($td, 'This is very important data'));

        $td = phpseclib_mcrypt_module_open('rijndael-128', '', 'cbc', '');
        phpseclib_mcrypt_generic_init($td, $key, $iv);
        $phpseclib = bin2hex(phpseclib_mcrypt_generic($td, 'This is very important data'));

        $this->assertEquals($mcrypt, $phpseclib);
    }

    /**
     * adapted from the example at http://php.net/manual/en/filters.encryption.php
     */
    public function testStream()
    {
        if (!extension_loaded('mcrypt')) {
            $this->markTestSkipped('mcrypt must be installed to compare the output of the shim to the original mcrypt');
        }

        $passphrase = 'My secret';
        $plaintext = 'Secret secret secret data';

        $iv = substr(md5('iv' . $passphrase, true), 0, 8);
        $key = substr(md5('pass1' . $passphrase, true) .
                      md5('pass2' . $passphrase, true), 0, 24);
        $opts = array('iv' => $iv, 'key' => $key);

        $expected = substr($plaintext . $plaintext, 0, 48);

        $fp = fopen('php://memory', 'wb+');
        stream_filter_append($fp, 'mcrypt.tripledes', STREAM_FILTER_WRITE, $opts);
        fwrite($fp, $plaintext . $plaintext);
        rewind($fp);
        $reference = bin2hex(fread($fp, 1024));
        fclose($fp);

        $fp = fopen('php://memory', 'wb+');
        stream_filter_append($fp, 'mcrypt.tripledes', STREAM_FILTER_WRITE, $opts);
        fwrite($fp, $plaintext);
        fwrite($fp, $plaintext);
        rewind($fp);
        $mcrypt = bin2hex(fread($fp, 1024));
        stream_filter_append($fp, 'mdecrypt.tripledes', STREAM_FILTER_READ, $opts);
        rewind($fp);
        $decrypted = fread($fp, 1024);
        fclose($fp);

        // this demonstrates that streams operate in continuous mode
        $this->assertEquals($reference, $mcrypt);

        // this demonstrates how to decrypt encrypted data
        $this->assertEquals($expected, $decrypted);

        $fp = fopen('php://memory', 'wb+');
        stream_filter_append($fp, 'phpseclib.mcrypt.tripledes', STREAM_FILTER_WRITE, $opts);
        fwrite($fp, $plaintext);
        fwrite($fp, $plaintext);
        rewind($fp);
        $compat = bin2hex(fread($fp, 1024));
        stream_filter_append($fp, 'phpseclib.mdecrypt.tripledes', STREAM_FILTER_READ, $opts);
        rewind($fp);
        $decrypted = fread($fp, 1024);
        fclose($fp);

        // this demonstrates that mcrypt's stream and phpseclib's stream's have identical output
        $this->assertEquals($mcrypt, $compat);

        // this demonstrates that phpseclib's stream successfully decrypts the encrypted string
        // since both mcrypt and phpseclib successfully decrypt to the same thing the outputs can be assumed to be matching
        $this->assertEquals($expected, $decrypted);

        // in the case of cbc the length is a multiple of the block size. extra characters are added
        // when enough are present for another block to be added
        $this->assertNotEquals(strlen($mcrypt), strlen($plaintext) * 2);
    }

    // i'd have a testRC4Stream method were it not for https://bugs.php.net/72535

    public function testShortKeyIVStream()
    {
        if (!extension_loaded('mcrypt')) {
            $this->markTestSkipped('mcrypt must be installed to compare the output of the shim to the original mcrypt');
        }

        $plaintext = 'Secret secret secret data';

        $iv = 'z';
        $key = 'z';
        $opts = array('iv' => $iv, 'key' => $key);

        $fp = fopen('php://memory', 'wb+');
        stream_filter_append($fp, 'mcrypt.tripledes', STREAM_FILTER_WRITE, $opts);
        fwrite($fp, $plaintext);
        rewind($fp);
        $mcrypt = bin2hex(fread($fp, 1024));
        fclose($fp);

        $fp = fopen('php://memory', 'wb+');
        stream_filter_append($fp, 'phpseclib.mcrypt.tripledes', STREAM_FILTER_WRITE, $opts);
        fwrite($fp, $plaintext);
        rewind($fp);
        $compat = bin2hex(fread($fp, 1024));
        fclose($fp);

        $this->assertEquals($mcrypt, $compat);
    }

    public function testBlowfish()
    {
        if (!extension_loaded('mcrypt')) {
            $this->markTestSkipped('mcrypt must be installed to compare the output of the shim to the original mcrypt');
        }

        $key = str_repeat('z', phpseclib_mcrypt_module_get_algo_key_size('blowfish'));
        $iv = str_repeat('z', phpseclib_mcrypt_module_get_algo_block_size('blowfish'));

        $plaintext = str_repeat('a', 100);

        $mcrypt = mcrypt_encrypt('blowfish', $key, $plaintext, 'cbc', $iv);
        $compat = phpseclib_mcrypt_encrypt('blowfish', $key, $plaintext, 'cbc', $iv);
        $this->assertEquals(bin2hex($mcrypt), bin2hex($compat));
    }

    public function testBlowfishShortKey()
    {
        if (!extension_loaded('mcrypt')) {
            $this->markTestSkipped('mcrypt must be installed to compare the output of the shim to the original mcrypt');
        }

        $iv = str_repeat('z', phpseclib_mcrypt_module_get_algo_block_size('blowfish'));

        $plaintext = str_repeat('a', 100);

        $key_source = 'abcdef';
        for ($i = 1; $i < strlen($key_source); $i++) {
            $key = substr($key_source, 0, $i);
            $mcrypt = mcrypt_encrypt('blowfish', $key, $plaintext, 'cbc', $iv);
            $compat = phpseclib_mcrypt_encrypt('blowfish', $key, $plaintext, 'cbc', $iv);
            $this->assertEquals(bin2hex($mcrypt), bin2hex($compat));
        }
    }

    /**
     * @group github10
     */
    public function test2DES()
    {
        if (!extension_loaded('mcrypt')) {
            $this->markTestSkipped('mcrypt must be installed to compare the output of the shim to the original mcrypt');
        }

        $key = '123456789abcdefg';

        $plaintext = 'Password:abc123';

        $td = mcrypt_module_open(MCRYPT_TRIPLEDES, '', MCRYPT_MODE_ECB, '');
        $iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
        mcrypt_generic_init($td, $key, $iv);
        $mcrypt = mcrypt_generic($td, $plaintext);
        mcrypt_generic_deinit($td);

        $td = phpseclib_mcrypt_module_open(MCRYPT_TRIPLEDES, '', MCRYPT_MODE_ECB, '');
        phpseclib_mcrypt_generic_init($td, $key, $iv);
        $compat = phpseclib_mcrypt_generic($td, $plaintext);
        phpseclib_mcrypt_generic_deinit($td);

        $this->assertEquals(bin2hex($mcrypt), bin2hex($compat));
    }

    public function testMcryptGenericWithTwoParamsPHPPre71()
    {
        if (version_compare(PHP_VERSION, '7.1.0') >= 0) {
            $this->markTestSkipped('PHPUnit_Framework_Error_Warning exception is thrown for legacy PHP versions only');
        }

        $this->setExpectedException('PHPUnit_Framework_Error_Warning');

        $td = phpseclib_mcrypt_module_open(MCRYPT_ARCFOUR, '', MCRYPT_MODE_STREAM, '');
        phpseclib_mcrypt_generic_init($td, 'xxx');
    }

    public function testMcryptGenericWithTwoParamsPHPPost71()
    {
        if (version_compare(PHP_VERSION, '7.1.0') < 0) {
            $this->markTestSkipped('ArgumentCountError exception is thrown for newer PHP versions only');
        }

        $this->setExpectedException('ArgumentCountError');

        $td = phpseclib_mcrypt_module_open(MCRYPT_ARCFOUR, '', MCRYPT_MODE_STREAM, '');
        phpseclib_mcrypt_generic_init($td, 'xxx');
    }

    public function providerForIVSizeChecks()
    {
        $tests = [
            [ '', MCRYPT_3DES, MCRYPT_MODE_ECB, 'generic', 8, '44448888', 8, false ],
            [ '', MCRYPT_3DES, MCRYPT_MODE_CBC, 'generic', 8, '44448888', 8, false ],
            [ '', MCRYPT_3DES, MCRYPT_MODE_CBC, 'generic', 0, '44448888', 8, 'Iv size incorrect; supplied length: 0, needed: 8' ],
            [ '', MCRYPT_3DES, MCRYPT_MODE_CBC, 'generic', 4, '44448888', 8, 'Iv size incorrect; supplied length: 4, needed: 8' ],
            [ '', MCRYPT_ARCFOUR, MCRYPT_MODE_STREAM, 'generic', 0, '44448888', 0, false ],
            [ '', MCRYPT_ARCFOUR, MCRYPT_MODE_STREAM, 'generic', 4, '44448888', 0, 'Iv size incorrect; supplied length: 4, needed: 0' ],
            [ '', MCRYPT_ARCFOUR, MCRYPT_MODE_STREAM, 'generic', 8, '44448888', 0, 'Iv size incorrect; supplied length: 8, needed: 0' ],
            [ '', MCRYPT_3DES, MCRYPT_MODE_ECB, 'decrypt', 0, '44448888', 8, false ],
            [ '', MCRYPT_3DES, MCRYPT_MODE_ECB, 'decrypt', 4, '44448888', 8, false ],
            [ '', MCRYPT_3DES, MCRYPT_MODE_ECB, 'decrypt', 8, '44448888', 8, false ],
            [ '', MCRYPT_3DES, MCRYPT_MODE_CBC, 'decrypt', 8, '44448888', 8, false ],
            [ '', MCRYPT_ARCFOUR, MCRYPT_MODE_STREAM, 'decrypt', 0, '44448888', 0, false ],
            // here comes a known, but acceptable difference between the ext and phpseclib:
            [ 'compat', MCRYPT_3DES, MCRYPT_MODE_ECB, 'generic', 0, '44448888', 8, false ],
            [ 'compat', MCRYPT_3DES, MCRYPT_MODE_ECB, 'generic', 4, '44448888', 8, false ],
            [ 'ext', MCRYPT_3DES, MCRYPT_MODE_ECB, 'generic', 0, '44448888', 8, PHP_VERSION_ID >= 70000 ? false : 'Iv size incorrect; supplied length: 0, needed: 8' ],
            [ 'ext', MCRYPT_3DES, MCRYPT_MODE_ECB, 'generic', 4, '44448888', 8, PHP_VERSION_ID >= 70000 ? false : 'Iv size incorrect; supplied length: 4, needed: 8' ],
        ];
        if (PHP_VERSION_ID >= 56000) {
            $tests+= [
                // the following produce errors in older versions of PHP but stopped as of PHP 5.6+
                [ '', MCRYPT_ARCFOUR, MCRYPT_MODE_STREAM, 'decrypt', 4, '44448888', 0, false ],
                [ '', MCRYPT_ARCFOUR, MCRYPT_MODE_STREAM, 'decrypt', 8, '44448888', 0, false ],
                // the following produced an error with a different message before PHP 5.6. mcrypt_compat uses the
                // PHP 5.6+ error messages.
                [ '', MCRYPT_3DES, MCRYPT_MODE_CBC, 'decrypt', 0, '44448888', 8, 'initialization vector of size 0, but size 8 is required' ],
                [ '', MCRYPT_3DES, MCRYPT_MODE_CBC, 'decrypt', 4, '44448888', 8, 'initialization vector of size 4, but size 8 is required' ]
            ];
        }

        $all_tests = [];
        foreach ($tests as $test) {
            if (empty($test[0])) {
                $test[0] = 'ext';
                $all_tests[] = $test;
                $test[0] = 'compat';
                $all_tests[] = $test;
            } else {
                $all_tests[] = $test;
            }
        }

        return $all_tests;
    }

    /**
     * @dataProvider providerForIVSizeChecks
     */
    public function testCompareIVSizeChecks($ext_or_compat, $cipher, $mode, $api, $input_iv_size, $input, $expected_iv_size, $expected_warning)
    {
        $this->assertSame(mcrypt_get_key_size($cipher, $mode), phpseclib_mcrypt_get_key_size($cipher, $mode));
        $this->assertSame($expected_iv_size, mcrypt_get_iv_size($cipher, $mode));
        $this->assertSame($expected_iv_size, phpseclib_mcrypt_get_iv_size($cipher, $mode));

        $key = str_repeat('X', phpseclib_mcrypt_get_key_size($cipher, $mode));
        $iv = str_repeat('Y', $input_iv_size);

        if ($ext_or_compat === 'ext' && !extension_loaded('mcrypt')) {
            $this->markTestSkipped('mcrypt extension not loaded');
        }

        if ($expected_warning) {
            $this->setExpectedException(PHPUnit_Framework_Error_Warning::class, $expected_warning);
        }

        if ($api === 'generic' && $ext_or_compat === 'ext') {
            $td = mcrypt_module_open($cipher, '', $mode, '');
            mcrypt_generic_init($td, $key, $iv);
            mcrypt_generic_deinit($td);
            mcrypt_module_close($td);
        } elseif ($api === 'generic') {
            $td = phpseclib_mcrypt_module_open($cipher, '', $mode, '');
            phpseclib_mcrypt_generic_init($td, $key, $iv);
            phpseclib_mcrypt_generic_deinit($td);
            phpseclib_mcrypt_module_close($td);
        } elseif ($ext_or_compat === 'ext') {
            mcrypt_encrypt($cipher, $key, $input, $mode, $iv);
        } else {
            phpseclib_mcrypt_encrypt($cipher, $key, $input, $mode, $iv);
        }
    }

    public function testTripleDESECBParameters()
    {
        $key_size = phpseclib_mcrypt_get_key_size(MCRYPT_3DES, MCRYPT_MODE_ECB);
        $this->assertSame(24, $key_size);
        $iv_size = phpseclib_mcrypt_get_iv_size(MCRYPT_3DES, MCRYPT_MODE_ECB);
        $this->assertSame(8, $iv_size);
    }

    public function mcryptModuleNameProvider()
    {
        return array(
            array('twofish', 'cbc', '\phpseclib\Crypt\Twofish'),
            array('rijndael-128', 'cbc', '\phpseclib\Crypt\Rijndael'),
            array('rijndael-192', 'cbc', '\phpseclib\Crypt\Rijndael'),
            array('des', 'cbc', '\phpseclib\Crypt\DES'),
            array('rijndael-256', 'cbc', '\phpseclib\Crypt\Rijndael'),
            array('blowfish', 'cbc', '\phpseclib\Crypt\Blowfish'),
            array('rc2', 'cbc', '\phpseclib\Crypt\RC2'),
            array('tripledes', 'cbc', '\phpseclib\Crypt\TripleDES'),
            array('arcfour', 'stream', '\phpseclib\Crypt\RC4')
        );
    }

    public function mcryptEncGetAlgorithmsNameProvider()
    {
        return array(
            array('twofish', 'cbc', 'TWOFISH'),
            array('rijndael-256', 'cbc', 'RIJNDAEL-'),
            array('des', 'cbc', 'DES'),
            array('blowfish', 'cbc', 'BLOWFISH'),
            array('rc2', 'cbc', 'RC2'),
            array('tripledes', 'cbc', 'TRIPLEDES'),
            array('arcfour', 'stream', 'ARCFOUR')
        );
    }

    public function mcryptBlockModuleNameProvider()
    {
        return array(
            array('cbc', true),
            array('ctr', true),
            array('ecb', true),
            array('ncfb', true),
            array('nofb', true),
            array('invalid-mode', false)
        );
    }

    public function mcryptBlockModuleAlgoNameProvider()
    {
        return array(
            array('rijndael-128', true),
            array('twofish', true),
            array('rijndael-192', true),
            array('des', true),
            array('rijndael-256', true),
            array('blowfish', true),
            array('rc2', true),
            array('tripledes', true),
            array('invalid-algorithm-name', false)
        );
    }

    public function mcryptModuleIsBlockModeProvider()
    {
        return array(
            array('cbc', true),
            array('ecb', true),
            array('invalid-mode-name', false)
        );
    }

    public function setExpectedException($name, $message = null, $code = null)
    {
        if (version_compare(PHP_VERSION, '7.0.0') < 0) {
            parent::setExpectedException($name, $message, $code);
            return;
        }
        switch ($name) {
            case 'PHPUnit_Framework_Error_Notice':
            case 'PHPUnit_Framework_Error_Warning':
                $name = str_replace('_', '\\', $name);
        }
        $this->expectException($name);
        if (!empty($message)) {
            $this->expectExceptionMessage($message);
        }
        if (!empty($code)) {
            $this->expectExceptionCode($code);
        }
    }
}
