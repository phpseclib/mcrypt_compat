<?php
class MCryptCompatTest extends PHPUnit_Framework_TestCase
{
    public function testAlgorithmList()
    {
        $this->assertInternalType('array', phpseclib_mcrypt_list_algorithms());
    }

    public function testListAlgorithms()
    {
        $this->assertInternalType('array', phpseclib_mcrypt_list_algorithms());
    }

    public function testAESBasicSuccess()
    {
        $key = str_repeat('z', 16);
        $iv = str_repeat('z', 16);

        // a plaintext / ciphertext of length 1 is of an insufficient length for cbc mode
        $plaintext = str_repeat('a', 16);

        $mcrypt = mcrypt_encrypt('rijndael-128', $key, $plaintext, 'cbc', $iv);
        $compat = phpseclib_mcrypt_encrypt('rijndael-128', $key, $plaintext, 'cbc', $iv);
        $this->assertEquals(bin2hex($mcrypt), bin2hex($compat));

        $ciphertext = $mcrypt;

        $mcrypt = mcrypt_decrypt('rijndael-128', $key, $ciphertext, 'cbc', $iv);
        $compat = phpseclib_mcrypt_decrypt('rijndael-128', $key, $ciphertext, 'cbc', $iv);
        $this->assertEquals($mcrypt, $compat);

        $decrypted = $mcrypt;
        $this->assertEquals($plaintext, $decrypted);
    }

    public function testAESDiffKeyLength()
    {
        $key = str_repeat('z', 24);
        $iv = str_repeat('z', 16);

        // a plaintext / ciphertext of length 1 is of an insufficient length for cbc mode
        $plaintext = str_repeat('a', 16);

        $mcrypt = mcrypt_encrypt('rijndael-128', $key, $plaintext, 'cbc', $iv);
        $compat = phpseclib_mcrypt_encrypt('rijndael-128', $key, $plaintext, 'cbc', $iv);
        $this->assertEquals(bin2hex($mcrypt), bin2hex($compat));
    }

    /**
     * @expectedException PHPUnit_Framework_Error_Warning
     */
    public function testBadParamsMcrypt()
    {
        mcrypt_encrypt('rijndael-128', 'abc', 'asdf', 'cbc', 'zz');
    }

    /**
     * pretty much the same thing as testBadParamsMcrypt
     *
     * @expectedException PHPUnit_Framework_Error_Warning
     */
    public function testBadParamsMcryptCompat()
    {
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
     * @expectedException PHPUnit_Framework_Error_Warning
     */
    public function testMiddleKey2()
    {
        $key = str_repeat('z', 20);
        $iv = str_repeat('z', 16);

        $plaintext = 'a';

        mcrypt_encrypt('rijndael-128', $key, $plaintext, 'cbc', $iv);
    }

    /**
     * phpseclib_mcrypt_generic() behaves in the same way
     *
     * @expectedException PHPUnit_Framework_Error_Warning
     */
    public function testMiddleKey3()
    {
        $key = str_repeat('z', 20);
        $iv = str_repeat('z', 16);

        $plaintext = 'a';

        phpseclib_mcrypt_encrypt('rijndael-128', $key, $plaintext, 'cbc', $iv);
    }

    /**
     * adapted from the example at http://php.net/manual/en/filters.encryption.php
     */
    public function testStream()
    {
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
}