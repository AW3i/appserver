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

    /**
     * The datasource name used to lookup in the naming directory.
     *
     * @var \AppserverIo\Lang\String
     */
    protected $lookupName;

    /**
     * The database query used to load the user's roles.
     *
     * @var \AppserverIo\Lang\String
     */
    protected $rolesQuery;

    /**
     * The database query used to load the user.
     *
     * @var \AppserverIo\Lang\String
     */
    protected $principalsQuery;

    /**
     * The ldap url of the ldap server
     *
     * @var string
     */
    protected $ldapUrl = null;

    /**
     * The ldap port of the ldap server
     *
     * @var string
     */
    protected $ldapPort = null;

    /**
     * bindDN
     *
     * @var string
     */
    protected $bindDN = null;

    /**
     * bindCredential
     *
     * @var string
     */
    protected $bindCredential = null;

    /**
     * The ldap servers distinguished base name
     *
     * @var string
     */
    protected $baseDN = null;

    /**
     * The ldap filter to search for
     *
     * @var string
     */
    protected $baseFilter = null;

    /**
     * rolesCtxDN
     *
     * @var string
     */
    protected $rolesCtxDN = null;

    /**
     * roleFilter
     *
     * @var string
     */
    protected $roleFilter = null;

    /**
     *
     *
     * @var string
     */
    protected $roleAttributeID = null;

    /**
     * roleNameAttributeID
     *
     * @var boolean
     */
    protected $roleNameAttributeID = null;

   /**
    * A flag indicating whether the user's role attribute
    * contains the fully distinguished name of a role object, or the users's role
    * attribute contains the role name. If false, the role name is taken from the
    * value of the user's role attribute. If true, the role attribute represents the
    * distinguished name of a role object.  The role name is taken from the value of
    * the roleNameAttributeId` attribute of the corresponding object.  In certain
    * directory schemas (e.g., Microsoft Active Directory), role (group)attributes in
    * the user object are stored as DNs to role objects instead of as simple names, in
    * which case, this property should be set to true. The default value of this
    * property is false.
    *
    * @var boolean
    */
    protected $roleAttributeIsDN;

    /**
     * parseRoleNameFromDN
     *
     * @var boolean
     */
    protected $parseRoleNameFromDN = null;

    /**
     * recursion
     *
     * @var int
     */
    protected $recursion = null;

    // simple flag to indicate is the validatePassword method was called
    protected $isPasswordValidated = false;

    /**
     * The ldap start tls flag. Enables/disables tls requests to the ldap server
     *
     * @var boolean
     */
    protected $ldapStartTls = null;

    /**
     *
     *
     * @var boolean
     */
    protected $allowEmptyPasswords = null;


    /**
     * Initialize the login module. This stores the subject, callbackHandler and sharedState and options
     * for the login session. Subclasses should override if they need to process their own options. A call
     * to parent::initialize() must be made in the case of an override.
     *
     * The following parameters can by default be passed from the configuration.
     *
     * lookupName:      The datasource name used to lookup in the naming directory
     * rolesQuery:      The database query used to load the user's roles
     * principalsQuery: The database query used to load the user
     *
     * @param \AppserverIo\Psr\Security\Auth\Subject                           $subject         The Subject to update after a successful login
     * @param \AppserverIo\Psr\Security\Auth\Callback\CallbackHandlerInterface $callbackHandler The callback handler that will be used to obtain the user identity and credentials
     * @param \AppserverIo\Collections\MapInterface                            $sharedState     A map shared between all configured login module instances
     * @param \AppserverIo\Collections\MapInterface                            $params          The parameters passed to the login module
     *
     * @return void
     */
    public function initialize(Subject $subject, CallbackHandlerInterface $callbackHandler, MapInterface $sharedState, MapInterface $params)
    {

        // call the parent method
        parent::initialize($subject, $callbackHandler, $sharedState, $params);

        $this->lookupName = new String($params->get(ParamKeys::LOOKUP_NAME));
        $this->rolesQuery = new String($params->get(ParamKeys::ROLES_QUERY));
        $this->principalsQuery = new String($params->get(ParamKeys::PRINCIPALS_QUERY));
        $this->userQuery = new String($params->get(ParamKeys::USER_QUERY));

        // initialize the hash encoding to use
        if ($params->exists(ParamKeys::URL)) {
            $this->ldapUrl = $params->get(ParamKeys::URL);
        }
        if ($params->exists(ParamKeys::PORT)) {
            $this->ldapPort = $params->get(ParamKeys::PORT);
        }
        if ($params->exists(ParamKeys::BIND_DN)) {
            $this->bindDN= $params->get(ParamKeys::BIND_DN);
        }
        if ($params->exists(ParamKeys::BIND_CREDENTIAL)) {
            $this->bindCredential = $params->get(ParamKeys::BIND_CREDENTIAL);
        }
        if ($params->exists(ParamKeys::BASE_FILTER)) {
            $this->baseFilter = $params->get(ParamKeys::BASE_FILTER);
        }
        if ($params->exists(ParamKeys::ROLES_CTX_DN)) {
            $this->rolesCtxDN = $params->get(ParamKeys::ROLES_CTX_DN);
        }
        if ($params->exists(ParamKeys::ROLE_FILTER)) {
            $this->roleFilter = $params->get(ParamKeys::ROLE_FILTER);
        }
        if ($params->exists(ParamKeys::ROLE_ATTRIBUTE_ID)) {
            $this->roleAttributeID = $params->get(ParamKeys::ROLE_ATTRIBUTE_ID);
        }
        if ($params->exists(ParamKeys::ROLE_NAME_ATTRIBUTE_ID)) {
            $this->roleNameAttributeID = $params->get(ParamKeys::ROLE_NAME_ATTRIBUTE_ID);
        }
        if ($params->exists(ParamKeys::ROLE_ATTRIBUTE_IS_DN)) {
            $this->roleAttributeIsDN = $params->get(ParamKeys::ROLE_ATTRIBUTE_IS_DN);
        }
        if ($params->exists(ParamKeys::PARSE_ROLE_NAME_FROM_DN)) {
            $this->parseRoleNameFromDN = $params->get(ParamKeys::PARSE_ROLE_NAME_FROM_DN);
        }
        if ($params->exists(ParamKeys::RECURSION)) {
            $this->recursion = $params->get(ParamKeys::RECURSION);
        }
        if ($params->exists(ParamKeys::IS_PASSWORD_VALIDATED)) {
            $this->isPasswordValidated = $params->get(ParamKeys::IS_PASSWORD_VALIDATED);
        }
        if ($params->exists(ParamKeys::START_TLS)) {
            $this->ldapStartTls = $params->get(ParamKeys::START_TLS);
        }
        if ($params->exists(ParamKeys::ALLOW_EMPTY_PASSWORDS)) {
            $this->allowEmptyPasswords = $params->get(ParamKeys::ALLOW_EMPTY_PASSWORDS);
        }
    }

    /**
     * Perform the authentication of username and password through ldap.
     * Following that if the ldap user is not registered the function will try to insert the user in the database.
     *
     * @return boolean TRUE when login has been successfull, else FALSE
     * @throws \AppserverIo\Psr\Security\Auth\Login\LoginException Is thrown if an error during login occured
     */
    public function login()
    {
        $this->loginOk = false;

        // array containing the username and password from the user's input
        list ($name, $password) = $this->getUsernameAndPassword();

        if ($name == null && $password == null) {
            $this->identity = $this->unauthenticatedIdentity;
        }

        if ($this->identity == null) {
            try {
                $this->identity = $this->createIdentity($name);
            } catch (\Exception $e) {
                throw new LoginException(sprintf('Failed to create principal: %s', $e->getMessage()));
            }
        }
        $ldap_connection = ldap_connect($this->ldapUrl, $this->ldapPort);

        if ($ldap_connection) {
            if ($this->ldapStartTls == 'true') {
                ldap_start_tls($ldap_connection);
            }

            //anonymous login
            if ($this->allowEmptyPasswords) {
                $bind = ldap_bind($ldap_connection);
            } else {
                $bind = ldap_bind($ldap_connection, $this->bindDN, $this->bindCredential);
            }

            // Replace username with the actual username of the user
            $this->$baseFilter = preg_replace("/username/", "$name", $this->$baseFilter);

            $search = ldap_search($ldap_connection, $this->bindDN, $this->$baseFilter);

            $entry = ldap_first_entry($ldap_connection, $search);
            $dn = ldap_get_dn($ldap_connection, $entry);

            if (!(isset($dn))) {
                throw new LoginException(sprintf('User not found in ldap directory'));
            }
        } else {
            throw new LoginException(sprintf('Couldn\'t connect to ldap server'));
        }

        $bind = ldap_bind($ldap_connection, $dn, $password);
        if ($bind == false) {
            throw new LoginException(sprintf('Username or password wrong'));
        }

        // query whether or not password stacking has been activated
        if ($this->getUseFirstPass()) {
            // add the username and password to the shared state map
            $this->sharedState->add(SharedStateKeys::LOGIN_NAME, $name);
            $this->sharedState->add(SharedStateKeys::LOGIN_PASSWORD, $this->credential);
        }

        $this->loginOk = true;
        return true;
    }

    /**
     * Returns the password for the user from the sharedMap data.
     *
     * @return void
     */
    public function getUsersPassword()
    {
        return null;
    }

    /**
     * Execute the rolesQuery against the lookupName to obtain the roles for the authenticated user.
     *
     * @return array Array containing the sets of roles
     * @throws \AppserverIo\Psr\Security\Auth\Login\LoginException Is thrown if password can't be loaded
     */
    protected function getRoleSets()
    {
        return Util::getRoleSets($this->getUsername(), new String($this->lookupName), new String($this->rolesQuery), $this);
    }

    /**
     * return's the authenticated user identity.
     *
     * @return \appserverio\psr\security\principalinterface the user identity
     */
    protected function getidentity()
    {
        return $this->identity;
    }
}
