<?php

/**
 * \AppserverIo\Appserver\Core\Api\Node\DoctrineListenersNodeTrait
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

/**
 * Abstract node that serves nodes having a listeners/listener child.
 *
 * @author    Tim Wagner <tw@appserver.io>
 * @copyright 2015 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io/appserver
 * @link      http://www.appserver.io
 */
trait DoctrineListenersNodeTrait
{

    /**
     * The listeners.
     *
     * @var array
     * @AS\Mapping(nodeName="doctrineListeners/doctrineListener", nodeType="array", elementType="AppserverIo\Appserver\Core\Api\Node\DoctrineListenersNode")
     */
    protected $listeners = array();

    /**
     * Array with the listeners.
     *
     * @param array $listeners The listeners
     *
     * @return void
     */
    public function setlisteners(array $listeners)
    {
        $this->listeners = $listeners;
    }

    /**
     * Array with the listeners.
     *
     * @return \AppserverIo\Appserver\Core\Api\Node\DirectoryNode[]
     */
    public function getlisteners()
    {
        return $this->listeners;
    }

    /**
     * Returns an array with the listeners as string value, each
     * prepended with the passed value.
     *
     * @param string $prepend Prepend to each listener
     *
     * @return The array with the listeners as string
     */
    public function getlistenersAsArray($prepend = null)
    {
        $listeners = array();
        foreach ($this->getlisteners() as $listener) {
            $listeners[] = sprintf('%s%s', $prepend, $listener->getNodeValue()->__toString());
        }
        return $listeners;
    }
}
