<?php
///**
// * Created by PhpStorm.
// * User: alex
// * Date: 9/5/16
// * Time: 9:15 AM
// */
//
//namespace AppserverIo\Appserver\ServletEngine\Security\Utils;
//
//
//class UtilFactory
//{
//
//    public static function createPasswordHash($hashAlgorithm, $salt, $hashEncoding, $hashCharset, String $name, String $password, $callback)
//    {
//        switch ($hashAlgorithm) {
//            case 'md5':
//                $newPassword = clone $password;
//                return $newPassword->md5();
//            case 'sha1':
//                return hash('sha1', $password);
//            case 'sha256':
//                return hash('sha256', $password);
//            case 'sha512':
//                return hash('sha512', $password);
//            case 'PASSWORD_BCRYPT':
//                return password_hash($password, PASSWORD_BCRYPT);
//            case 'default':
//                return password_hash($password, PASSWORD_DEFAULT);
//        }
//    }
//}