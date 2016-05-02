<?php
class MCryptCompatTest extends PHPUnit_Framework_TestCase
{
    public function testAlgorithmList()
    {
        $this->assertInternalType('array', phpseclib_mcrypt_list_algorithms());
    }
    
    public function testAESBasicSuccess()
    {
        $mcrypt = bin2hex(mcrypt_encrypt('rijndael-128', str_repeat('a', 16), 'asdf', 'cbc', str_repeat('a', 16)));
        $compat = bin2hex(phpseclib_mcrypt_encrypt('rijndael-128', str_repeat('a', 16), 'asdf', 'cbc', str_repeat('a', 16)));
        $this->assertEquals($mcrypt, $compat);
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
}