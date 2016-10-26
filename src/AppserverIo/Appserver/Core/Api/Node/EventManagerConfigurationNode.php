<?php

/**
 * \AppserverIo\Appserver\Core\Api\Node\EventManagerConfigurationNode
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

namespace AppserverIo\Appserver\Core\Api\Node;

use AppserverIo\Description\Api\Node\AbstractNode;

/**
 * DTO to transfer an entity manager's event manager configuration.
 *
 * @author    Tim Wagner <tw@appserver.io>
 * @copyright 2015 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io/appserver
 * @link      http://www.appserver.io
 */
class EventManagerConfigurationNode extends AbstractNode
{

    /**
     * A doctrine listeners knode trait.
     *
     * @var \AppserverIo\Appserver\Core\Api\Node\DoctrineListenersNodeTrait
     */
    use DoctrineListenersNodeTrait;

    /**
     * The class name for the event manager configuration driver.
     *
     * @var string
     * @AS\Mapping(nodeType="string")
     */
    protected $type;

    /**
     * The factory class name for the event manager configuration driver.
     *
     * @var string
     * @AS\Mapping(nodeType="string")
     */
    protected $factory;

    /**
     * Returns the class name for the event manager configuration driver.
     *
     * @return string The class name for the event manager configuration driver
     */
    public function getType()
    {
        return $this->type;
    }

    /**
     * Returns the factory class name for the event manager configuration driver.
     *
     * @return string The factory class name for the event manager configuration driver
     */
    public function getFactory()
    {
        return $this->factory;
    }
}
