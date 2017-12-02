<?php
namespace asinfotrack\yii2\jwt\helpers;

/**
 * Class used to represent decoded token contents
 *
 * @author Pascal Mueller, AS infotrack AG
 * @link http://www.asinfotrack.ch
 * @license AS infotrack AG license / MIT, see provided license file
 */
class JwtTokenDecodingResult extends \asinfotrack\yii2\jwt\helpers\JwtTokenContentBase
{

	/**
	 * Constructor used when initializing a token with decoded result data
	 *
	 * @param array $header the prepared header data of the token
	 * @param array $payload the prepared payload of the token
	 * @param array $config name-value pairs that will be used to initialize the object properties
	 */
	public function __construct($header=[], $payload=[], $config=[])
	{
		$this->header = $header;
		$this->payload = $payload;
		parent::__construct($config);
	}

}
