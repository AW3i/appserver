<?php
/**
 * Created by PhpStorm.
 * User: alex
 * Date: 9/5/16
 * Time: 2:21 PM
 */

namespace AppserverIo\Appserver\ServletEngine\Security\Utils;


class HashKeys
{
    /**
     * They key for the "md5" hash algorithm
     *
     * @var string
     */
    const MD5 = 'md5';

    /**
     * They key for the "sha1" hash algorithm
     *
     * @var string
     */
    const SHA1 = 'sha1';

    /**
     * They key for the "sha256" hash algorithm
     *
     * @var string
     */
    const SHA256 = 'sha256';

    /**
     * They key for the "sha512" hash algorithm
     *
     * @var string
     */
    const SHA512 = 'sha512';
}