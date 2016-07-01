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
}