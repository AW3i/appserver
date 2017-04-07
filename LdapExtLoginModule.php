<?php

/**
 * AppserverIo\Appserver\ServletEngine\Security\Auth\Spi\LdapLoginModule.php
 *
 * NOTICE OF LICENSE
 *
 * This source file is subject to the Open Software License (OSL 3.0)
 * that is available through the world-wide-web at this URL:
 * http://opensource.org/licenses/osl-3.0.php
 *
 * PHP version 5
 *
 * @author    Alexandros Weigl <a.weigl@techdivision.com>
 * @copyright 2017 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io/appserver
 * @link      http://www.appserver.io
 */

namespace AppserverIo\Appserver\ServletEngine\Security\Auth\Spi;

use AppserverIo\Lang\String;
use AppserverIo\Lang\Boolean;
use AppserverIo\Collections\HashMap;
use AppserverIo\Collections\MapInterface;
use AppserverIo\Psr\Security\Auth\Subject;
use AppserverIo\Psr\Security\Auth\Login\LoginException;
use AppserverIo\Psr\Security\Auth\Login\FailedLoginException;
use AppserverIo\Psr\Security\Auth\Callback\CallbackHandlerInterface;
use AppserverIo\Appserver\ServletEngine\Security\SecurityException;
use AppserverIo\Appserver\ServletEngine\Security\Utils\Util;
use AppserverIo\Appserver\ServletEngine\Security\Utils\ParamKeys;
use AppserverIo\Appserver\ServletEngine\Security\Utils\SharedStateKeys;
use AppserverIo\Appserver\ServletEngine\RequestHandler;
use AppserverIo\Appserver\ServletEngine\Security\SimpleGroup;

/**
 * This valve will check if the actual request needs authentication.
 *
 * @author    Alexandros Weigl <a.weigl@techdivision.com>
 * @copyright 2017 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io/appserver
 * @link      http://www.appserver.io
 */
class LdapLoginmodule extends UsernamePasswordLoginModule
{
  // see AbstractServerLoginModule
    const ROLES_CTX_DN_OPT = "rolesCtxDN";
    const ROLE_ATTRIBUTE_ID_OPT = "roleAttributeID";
    const ROLE_ATTRIBUTE_IS_DN_OPT = "roleAttributeIsDN";
    const ROLE_NAME_ATTRIBUTE_ID_OPT = "roleNameAttributeID";
    const PARSE_ROLE_NAME_FROM_DN_OPT = "parseRoleNameFromDN";
    const BIND_DN = "bindDN";
    const BIND_CREDENTIAL = "bindCredential";
    const BASE_CTX_DN = "baseCtxDN";
    const BASE_FILTER_OPT = "baseFilter";
    const ROLE_FILTER_OPT = "roleFilter";
    const ROLE_RECURSION = "roleRecursion";
    const DEFAULT_ROLE = "defaultRole";
    const SEARCH_TIME_LIMIT_OPT = "searchTimeLimit";
    const SEARCH_SCOPE_OPT = "searchScope";
    const SECURITY_DOMAIN_OPT = "jaasSecurityDomain";
    const DISTINGUISHED_NAME_ATTRIBUTE_OPT = "distinguishedNameAttribute";
    const PARSE_USERNAME = "parseUsername";
    const USERNAME_BEGIN_STRING = "usernameBeginString";
    const USERNAME_END_STRING = "usernameEndString";
    const ALLOW_EMPTY_PASSWORDS = "allowEmptyPasswords";
    const REFERRAL_USER_ATTRIBUTE_ID_TO_CHECK = "referralUserAttributeIDToCheck";
    const ALL_VALID_OPTIONS = array( ROLES_CTX_DN_OPT,
       ROLE_ATTRIBUTE_ID_OPT,
       ROLE_ATTRIBUTE_IS_DN_OPT,
       ROLE_NAME_ATTRIBUTE_ID_OPT,
       PARSE_ROLE_NAME_FROM_DN_OPT,
       BIND_DN,
       BIND_CREDENTIAL,
       BASE_CTX_DN,
       BASE_FILTER_OPT,
       ROLE_FILTER_OPT,
       ROLE_RECURSION,
       DEFAULT_ROLE,
       SEARCH_TIME_LIMIT_OPT,
       SEARCH_SCOPE_OPT,
       SECURITY_DOMAIN_OPT,
       DISTINGUISHED_NAME_ATTRIBUTE_OPT,
       PARSE_USERNAME,
       USERNAME_BEGIN_STRING,
       USERNAME_END_STRING,
       ALLOW_EMPTY_PASSWORDS,
       REFERRAL_USER_ATTRIBUTE_ID_TO_CHECK,

       Context.INITIAL_CONTEXT_FACTORY,
       Context.OBJECT_FACTORIES,
       Context.STATE_FACTORIES,
       Context.URL_PKG_PREFIXES,
       Context.PROVIDER_URL,
       Context.DNS_URL,
       Context.AUTHORITATIVE,
       Context.BATCHSIZE,
       Context.REFERRAL,
       Context.SECURITY_PROTOCOL,
       Context.SECURITY_AUTHENTICATION,
       Context.SECURITY_PRINCIPAL,
       Context.SECURITY_CREDENTIALS,
       Context.LANGUAGE,
       Context.APPLET
    );

    protected $bindDN;

    protected $bindCredential;

    protected $baseDN;

    protected $baseFilter;

    protected $rolesCtxDN;

    protected $roleFilter;

    protected $roleAttributeID;

    protected $roleNameAttributeID;

    protected $roleAttributeIsDN;

    protected $parseRoleNameFromDN;

    protected $recursion = 0;

    protected $searchTimeLimit = 10000;

    protected $searchScope = SearchControls.SUBTREE_SCOPE;

    protected $distinguishedNameAttribute;

    protected $parseUsername;

    protected $usernameBeginString;

    protected $usernameEndString;

    // simple flag to indicate is the validatePassword method was called
    protected $isPasswordValidated = false;

    protected $referralUserAttributeIDToCheck = null;

    private $userRoles;

    public function initialize($subject, $callbackHandler, $sharedState, $options)
    {
       // addValidOptions(ALL_VALID_OPTIONS);
       // super.initialize(subject, callbackHandler, sharedState, options);
        $this->userRoles = new SimpleGroup("Roles");
    }

   /**
    Overridden to return an empty password string as typically one cannot obtain a
    user's password. We also override the validatePassword so this is ok.
    @return and empty password String
    */
    protected function getUsersPassword()
    {
        return "";
    }

    protected function getRoleSets()
    {
        if (!(isset($isPasswordValidated)) && $this->getIdentity() !== $unauthenticatedIdentity) {
            try {
                $username = $this->getUsername();
               //$logger->traceBindingLDAPUsername($username);
                $this->createLdapInitContext($username, null);
                $this->defaultRole();
            } catch (Exception $e) {
                throw new LoginException($e);
            }
        }
        $roleSets = new SimpleGroup($userRoles);
        return $roleSets;
    }

    protected function validatePassword($inputPassword, $expectedPassword)
    {
        $isPasswordValidated = true;
        $isValid = false;
        if (len($inputPassword) === 0) {
            $allowEmptyPasswords = false;
            $flag = $options->get(ALLOW_EMPTY_PASSWORDS);
            $allowEmptyPasswords = Boolean.valueOf(flag).booleanValue(); //????
        }
        if (!(isset($allowEmptyPasswords))) {
            //logger
            return false;
        }

        try {
            $username = $this->getUsername();
            $isValid = $this->createLdapInitContext($username, $inputPassword);
            $this->defaultRole();
            $isValid = true;
        } catch (Exception e) {
            throw new Exception();
        }
        return $isValid;
    }

    protected function defaultRole()
    {

        $defaultRole = options.get(DEFAULT_ROLE);
        try {
            if ($defaultRole === null || $defaultRole === '') {
                return;
            }
            $principal = parent::createIdentity($defaultRole);
            //logger
            $userRoles->addMember($principal);
        } catch (Exception $e) {
        //logger
        }
    }

    private function createLdapInitContext($username, $objectCredential)
    {
        $bindDN = $options->get(BIND_DN);
        $bindCredential = $options->get(BIND_CREDENTIAL)
        if (($bindCredential !== null) && Util::isPasswordCommand($bindCredential)) {
            $bindCredential = Util::loadPassword($bindCredential);
        }
        $securityDomain = $options->get(SECURITY_DOMAIN_OPT);
        if ($securityDomain != null) {
            $serviceName = new ObjectName($securityDomain);
            $tmp = DecodeAction::decode($bindCredential, $serviceName);
            $bindCredential = new String($tmp);
        }
        if ($bindCredential !== null && SecurityVaultUtil::isVaultFormat($bindCredential)) {
            
        }
    }
}
