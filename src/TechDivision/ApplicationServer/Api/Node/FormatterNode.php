<?php

/**
 * TechDivision\ApplicationServer\Api\Node\FormatterNode
 *
 * NOTICE OF LICENSE
 *
 * This source file is subject to the Open Software License (OSL 3.0)
 * that is available through the world-wide-web at this URL:
 * http://opensource.org/licenses/osl-3.0.php
 */
namespace TechDivision\ApplicationServer\Api\Node;

/**
 * DTO to transfer formatter information.
 *
 * @package TechDivision\ApplicationServer
 * @copyright Copyright (c) 2013 <info@techdivision.com> - TechDivision GmbH
 * @license http://opensource.org/licenses/osl-3.0.php
 *          Open Software License (OSL 3.0)
 * @author Tim Wagner <tw@techdivision.com>
 */
class FormatterNode extends AbstractNode
{

    /**
     * The formatter's class name.
     *
     * @var string
     * @AS\Mapping(nodeType="string")
     */
    protected $type;

    /**
     * The handler params to use.
     *
     * @var array<\TechDivision\ApplicationServer\Api\Node\ParamNode>
     * @AS\Mapping(nodeName="params/param", nodeType="array", elementType="TechDivision\ApplicationServer\Api\Node\ParamNode")
     */
    protected $params = array();

    /**
     * Returns information about the formatter's class name.
     *
     * @return string The formatter's class name
     */
    public function getType()
    {
        return $this->type;
    }

    /**
     * Array with the handler params to use.
     *
     * @return array<\TechDivision\ApplicationServer\Api\Node\ParamNode>
     */
    public function getParams()
    {
        return $this->params;
    }
}