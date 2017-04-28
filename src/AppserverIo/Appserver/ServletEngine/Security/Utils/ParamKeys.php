<?php

/**
 * AppserverIo\Appserver\ServletEngine\Security\Utils\ParamKeys
 *
 * NOTICE OF LICENSE
 *
 * This source file is subject to the Open Software License (OSL 3.0)
 * that is available through the world-wide-web at this URL:
 * http://opensource.org/licenses/osl-3.0.php
 *
 * PHP version 5
 *
 * @author    Tim Wagner <tw@appserver.io>
 * @copyright 2015 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io/appserver
 * @link      http://www.appserver.io
 */

namespace AppserverIo\Appserver\ServletEngine\Security\Utils;

/**
 * Utility class that contains the parameter keys.
 *
 * @author    Tim Wagner <tw@appserver.io>
 * @copyright 2015 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io/appserver
 * @link      http://www.appserver.io
 */
class ParamKeys
{

    /**
     * The key for the "lookupName" parameter.
     *
     * @var string
     */
    const LOOKUP_NAME = 'lookupName';

    /**
     * The key for the "principalsQuery" parameter.
     *
     * @var string
     */
    const PRINCIPALS_QUERY = 'principalsQuery';

    /**
     * The key for the "rolesQuery" parameter.
     *
     * @var string
     */
    const ROLES_QUERY = 'rolesQuery';

    /**
     * The key for the "passwordStacking" parameter.
     *
     * @var string
     */
    const PASSWORD_STACKING = 'passwordStacking';

    /**
     * The key for the "hashAlgorithm" parameter.
     *
     * @var string
     */
    const HASH_ALGORITHM = 'hashAlgorithm';

    /**
     * The key for the "hashEncoding" parameter.
     *
     * @var string
     */
    const HASH_ENCODING = 'hashEncoding';

    /**
     * The key for the "hashCharset" parameter.
     *
     * @var string
     */
    const HASH_CHARSET = 'hashCharset';

    /**
     * The key for the "ignorePasswordCase" parameter.
     *
     * @var string
     */
    const IGNORE_PASSWORD_CASE = 'ignorePasswordCase';

    /**
     * The key for the "principalClass" parameter.
     *
     * @var string
     */
    const PRINCIPAL_CLASS = 'principalClass';

    /**
     * The key for the "unauthenticatedIdentity" parameter.
     *
     * @var string
     */
    const UNAUTHENTICATED_IDENTITY = 'unauthenticatedIdentity';

    /**
     * The key for the "digestCallback" parameter.
     *
     * @var string
     */
    const DIGEST_CALLBACK = 'digestCallback';

    /**
     * The key for the "userPathPrefix" parameter.
     *
     * @var string
     */
    const USER_PATH_PREFIX = 'userPathPrefix';

    /**
     * The key for the "rolesPathPrefix" parameter.
     *
     * @var string
     */
    const ROLES_PATH_PREFIX = 'rolesPathPrefix';

    /**
     * The key for the "url" parameter.
     *
     * @var string
     */
    const URL = 'url';

    /**
     * The key for the "port" parameter.
     *
     * @var string
     */
    const PORT = 'port';

    /**
     * The key for the "bindDistinguishedName" parameter.
     *
     * @var string
     */
    const BIND_DN = 'bindDistinguishedName';

    /**
     * The key for the "bindCredential" parameter.
     *
     * @var string
     */
    const BIND_CREDENTIAL = 'bindCredential';

    /**
     * The key for the "baseDN" parameter.
     *
     * @var string
     */
    const BASE_DN = 'baseDN';

    /**
     * The key for the "baseFilter" parameter.
     *
     * @var string
     */
    const BASE_FILTER = 'baseFilter';

    /**
     * The key for the "rolesCtxDN" parameter.
     *
     * @var string
     */
    const ROLES_CTX_DN = 'rolesCtxDN';

    /**
     * The key for the "roleFilter" parameter.
     *
     * @var string
     */
    const ROLE_FILTER = 'roleFilter';

    /**
     * The key for the "roleAttributeID" parameter.
     *
     * @var string
     */
    const ROLE_ATTRIBUTE_ID = 'roleAttributeID';

    /**
     * The key for the "roleNameAttributeID" parameter.
     *
     * @var string
     */
    const ROLE_NAME_ATTRIBUTE_ID = 'roleNameAttributeID';

    /**
     * The key for the "roleAttributeIsDn" parameter.
     *
     * @var string
     */
    const ROLE_ATTRIBUTE_IS_DN = 'roleAttributeIsDN';

    /**
     * The key for the "parseRoleNameFromDn" parameter.
     *
     * @var string
     */
    const PARSE_ROLE_NAME_FROM_DN = 'parseRoleNameFromDN';

    /**
     * The key for the "recursion" parameter.
     *
     * @var string
     */
    const RECURSION = 'recursion';

    /**
     * The key for the "isPasswordValidated" parameter.
     *
     * @var string
     */
    const IS_PASSWORD_VALIDATED = 'isPasswordValidated';

    /**
     * The key for the "StartTls";
     */
    const START_TLS = 'startTls';

    /**
     * The key for the "userFilter" parameter.
     *
     * @var string
     */
    const USER_FILTER = 'userFilter';

    /**
     * The key for the "roleFilter" parameter.
     *
     * @var string
     */
    const ROLE_FILTER = 'roleFilter';

    /**
     * The key for the "allowEmptyPasswords" parameter.
     *
     * @var string
     */
    const ALLOW_EMPTY_PASSWORDS = 'allowEmptyPasswords';



    /**
     * This is a utility class, so protect it against direct instantiation.
     */
    private function __construct()
    {
    }

    /**
     * This is a utility class, so protect it against cloning.
     *
     * @return void
     */
    private function __clone()
    {
    }
}
