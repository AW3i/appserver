<?php

/**
 * TechDivision\ApplicationServer\Api\Node\ProcessorNode
 *
 * NOTICE OF LICENSE
 *
 * This source file is subject to the Open Software License (OSL 3.0)
 * that is available through the world-wide-web at this URL:
 * http://opensource.org/licenses/osl-3.0.php
 */
namespace TechDivision\ApplicationServer\Api\Node;

/**
 * DTO to transfer processor information.
 *
 * @package TechDivision\ApplicationServer
 * @copyright Copyright (c) 2013 <info@techdivision.com> - TechDivision GmbH
 * @license http://opensource.org/licenses/osl-3.0.php
 *          Open Software License (OSL 3.0)
 * @author Tim Wagner <tw@techdivision.com>
 */
class ProcessorNode extends AbstractNode
{

    /**
     * The processor class name.
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
     * Array with the handler params to use.
     *
     * @return array<\TechDivision\ApplicationServer\Api\Node\ParamNode>
     */
    public function getParams()
    {
        return $this->params;
    }
}