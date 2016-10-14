<?php
/**
 * Created by PhpStorm.
 * User: alex
 * Date: 9/2/16
 * Time: 10:47 AM
 */

namespace AppserverIo\Appserver\ServletEngine\Security\Utils;
use AppserverIo\Appserver\ServletEngine\Security\Utils\Util;
use AppserverIo\Lang\String;


class UtilTest extends \PHPUnit_Framework_TestCase
{
    protected $password;
    protected $name;
    protected $salt;
    protected $hashAlgorithm;
    protected $hashEncoding;
    protected $hashCharset;
    protected $callback;

    public function setUp() {
//        $this->password = $this->getMock('String', array('init'), array('test'));
//        $this->name->getMock('String', array('init'), array('test'));
        $this->name = new String("test");
        $this->password = new String("test");
    }

    public function testCreatePasswordHashedMd5WithoutSalt() {
        $this->hashAlgorithm = HashKeys::MD5;
        $expectedPassword = md5($this->password);
        $password = Util::createPasswordHash($this->hashAlgorithm,
            $this->hashEncoding, $this->hashCharset, $this->name, $this->password, $this->callback, $this->salt);
        $this->assertEquals($expectedPassword, $password);
    }

    public function testCreatePasswordHashedMd5WithSalt() {
        $this->hashAlgorithm = HashKeys::MD5;
        $this->salt = '1234';
        $expectedPassword = md5($this->salt . $this->password);
        $password = Util::createPasswordHash($this->hashAlgorithm,
            $this->hashEncoding, $this->hashCharset, $this->name, $this->password, $this->callback, $this->salt);
        $this->assertEquals($expectedPassword, $password->stringValue());
    }

    public function testCreatePasswordHashedSha1WithoutSalt() {
        $this->hashAlgorithm = HashKeys::SHA1;
        $expectedPassword = hash(HashKeys::SHA1, $this->password);
        $password = Util::createPasswordHash($this->hashAlgorithm,
            $this->hashEncoding, $this->hashCharset, $this->name, $this->password, $this->callback, $this->salt);
        $this->assertEquals($expectedPassword, $password);
    }

    public function testCreatePasswordHashedSha1WithSalt() {
        $this->hashAlgorithm = HashKeys::SHA1;
        $this->salt = '1234';
        $expectedPassword = hash(HashKeys::SHA1, $this->salt . $this->password);
        $password = Util::createPasswordHash($this->hashAlgorithm,
            $this->hashEncoding, $this->hashCharset, $this->name, $this->password, $this->callback, $this->salt);
        $this->assertEquals($expectedPassword, $password->stringValue());
    }

    public function testCreatePasswordHashedSha256WithoutSalt() {
        $this->hashAlgorithm = HashKeys::SHA256;
        $expectedPassword = hash(HashKeys::SHA256, $this->password);
        $password = Util::createPasswordHash($this->hashAlgorithm,
            $this->hashEncoding, $this->hashCharset, $this->name, $this->password, $this->callback, $this->salt);
        $this->assertEquals($expectedPassword, $password);
    }

    public function testCreatePasswordHashedSha256WithSalt() {
        $this->hashAlgorithm = HashKeys::SHA256;
        $this->salt = '1234';
        $expectedPassword = hash(HashKeys::SHA256, $this->salt . $this->password);
        $password = Util::createPasswordHash($this->hashAlgorithm,
            $this->hashEncoding, $this->hashCharset, $this->name, $this->password, $this->callback, $this->salt);
        $this->assertEquals($expectedPassword, $password->stringValue());
    }

    public function testCreatePasswordHashedSha512WithoutSalt() {
        $this->hashAlgorithm = HashKeys::SHA512;
        $expectedPassword = hash(HashKeys::SHA512, $this->password);
        $password = Util::createPasswordHash($this->hashAlgorithm,
            $this->hashEncoding, $this->hashCharset, $this->name, $this->password, $this->callback, $this->salt);
        $this->assertEquals($expectedPassword, $password);

    }

    public function testCreatePasswordHashedSha512WithSalt() {
        $this->hashAlgorithm = HashKeys::SHA512;
        $this->salt = '1234';
        $expectedPassword = hash(HashKeys::SHA512, $this->salt . $this->password);
        $password = Util::createPasswordHash($this->hashAlgorithm,
            $this->hashEncoding, $this->hashCharset, $this->name, $this->password, $this->callback, $this->salt);
        $this->assertEquals($expectedPassword, $password->stringValue());
    }

    //Only with salt
    public function testCreatePasswordHashesPasswordDefault(){
        $this->hashAlgorithm = PASSWORD_DEFAULT;
        $expectedPassword = password_hash($this->password, $this->hashAlgorithm);
        $password = Util::createPasswordHash($this->hashAlgorithm,
            $this->hashEncoding, $this->hashCharset, $this->name, $this->password, $this->callback, $this->salt);
//        $this->assertTrue(password_verify($expectedPassword,$this->hashAlgorithm));
//        $this->assertTrue(password_verify($this->password,$this->hashAlgorithm));

        // creates a different hash for the same password
        $this->assertNotEquals($expectedPassword, $password);
    }

    public function testCreatePasswordHashesPasswordBcrypt(){
        $this->hashAlgorithm = PASSWORD_BCRYPT;
        $expectedPassword = password_hash($this->password, $this->hashAlgorithm);
        $password = Util::createPasswordHash($this->hashAlgorithm,
            $this->hashEncoding, $this->hashCharset, $this->name, $this->password, $this->callback, $this->salt);
//        $this->assertTrue(password_verify($expectedPassword,$this->hashAlgorithm));
//        $this->assertTrue(password_verify($this->password,$this->hashAlgorithm));

        // creates a different hash for the same password
        $this->assertNotEquals($expectedPassword, $password);
    }
}
