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
     * The ldap servers distinguished base name
     *
     * @var string
     */
    protected $ldapBaseDistinguishedName = null;

    /**
     * The ldap object class to use for the query
     *
     * @var string
     */
    protected $ldapObjectClass = null;

    /**
     * The ldap start tls flag. Enables/disables tls requests to the ldap server
     *
     * @var boolean
     */
    protected $ldapStartTls = null;

    /**
     * The userQuery to find the user
     *
     * @var \Appserver\Io\Lang\String
     */
    protected $userQuery = null;

    /**
     * The insertUserQuery to insert the new ldap user
     *
     * @var \Appserver\Io\Lang\String
     */
    protected $insertUserQuery = null;

    /**
     * The insertRoleQuery to insert the new ldap role
     *
     * @var \Appserver\Io\Lang\String
     */
    protected $insertRoleQuery = null;

    /**
     * The insertPersonQuery to insert the new ldap person
     *
     * @var \Appserver\Io\Lang\String
     */
    protected $insertPersonQuery = null;

    /**
     * The default role to find
     *
     * @var \Appserver\Io\Lang\String
     */
    protected $defaultRoleQuery = null;
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
        if ($params->exists(ParamKeys::LDAP_URL)) {
            $this->ldapUrl = $params->get(ParamKeys::LDAP_URL);
        }
        if ($params->exists(ParamKeys::LDAP_PORT)) {
            $this->ldapPort = $params->get(ParamKeys::LDAP_PORT);
        }
        if ($params->exists(ParamKeys::LDAP_BASE_DISTINGUISHED_NAME)) {
            $this->ldapBaseDistinguishedName = $params->get(ParamKeys::LDAP_BASE_DISTINGUISHED_NAME);
        }
        if ($params->exists(ParamKeys::LDAP_OBJECT_CLASS)) {
            $this->ldapObjectClass = $params->get(ParamKeys::LDAP_OBJECT_CLASS);
        }
        if ($params->exists(ParamKeys::LDAP_START_TLS)) {
            $this->ldapStartTls = $params->get(ParamKeys::LDAP_START_TLS);
        }
        if ($params->exists(ParamKeys::INSERT_USER_QUERY)) {
            $this->insertUserQuery = $params->get(ParamKeys::INSERT_USER_QUERY);
        }
        if ($params->exists(ParamKeys::INSERT_ROLE_QUERY)) {
            $this->insertRoleQuery = $params->get(ParamKeys::INSERT_ROLE_QUERY);
        }
        if ($params->exists(ParamKeys::INSERT_PERSON_QUERY)) {
            $this->insertPersonQuery = $params->get(ParamKeys::INSERT_PERSON_QUERY);
        }
        if ($params->exists(ParamKeys::DEFAULT_ROLE_QUERY)) {
            $this->defaultRoleQuery = $params->get(ParamKeys::DEFAULT_ROLE_QUERY);
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
            $bind = ldap_bind($ldap_connection);

            $filter = "(&(objectClass=$this->ldapObjectClass)(uid=$name))";
            $search = ldap_search($ldap_connection, $this->ldapBaseDistinguishedName, $filter);

            $entry = ldap_first_entry($ldap_connection, $search);
            $dn = ldap_get_dn($ldap_connection, $entry);

            if (!(isset($dn))) {
                throw new LoginException(sprintf('User not found in ldap directory'));
            }
            //get the ldap object for the current user
            $ldapUserAttributes = ldap_get_attributes($ldap_connection, $entry);

            $email = $ldapUserAttributes['mail'][0];
            $firstname = $ldapUserAttributes['givenName'][0];
            $lastname = $ldapUserAttributes['sn'][0];
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

        // Check if the ldap user exists
        if (!(Util::isUserRegistered($this->getUsername(), new String($this->lookupName), new String($this->userQuery)))) {
            //get the default role id
            $defaultRoleId = Util::getDefaultRole(new String($this->lookupName), $this->defaultRoleQuery);
            //Insert the ldap user to the local database
            Util::insertUser($this->getUsername(), new String($this->lookupName), $this->insertUserQuery, $this->insertRoleQuery, $defaultRoleId, $this->insertPersonQuery, $email, $firstname, $lastname);
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
