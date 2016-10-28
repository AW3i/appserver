<?php
/**
 * \AppserverIo\Appserver\PersistenceContainer\Doctrine\V2\DoctrineListenerFactory.php
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

namespace AppserverIo\Appserver\PersistenceContainer\Doctrine\V2;

/**
 * Factory implementation for a Doctrine Listener Array
 *
 * @author    Tim Wagner <tw@appserver.io>
 * @copyright 2015 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io/appserver
 * @link      http://www.appserver.io
 */
class DoctrineListenerFactory
{
    public static function build($eventManager, $cachedAnnotationReader, $listeners = array())
    {
        foreach ($listeners as $listener) {
            if (class_exists($listener)) {
                $tempListener = new $listener();
                $tempListener->setAnnotationReader($cachedAnnotationReader);
                $eventManager->addEventSubscriber($tempListener);
            } else {
                throw new Exception("Class $listener not found");
            }
        }
    }
}
