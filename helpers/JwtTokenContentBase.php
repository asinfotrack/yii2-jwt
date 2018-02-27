<?php
namespace asinfotrack\yii2\jwt\helpers;

/**
 * Base class which gets used to work with contents of a jwt token
 *
 * @author Pascal Mueller, AS infotrack AG
 * @link http://www.asinfotrack.ch
 * @license AS infotrack AG license / MIT, see provided license file
 */
abstract class JwtTokenContentBase extends \yii\base\BaseObject
{

	/**
	 * @var array holds the headers of the jwt content
	 */
	protected $header = [];

	/**
	 * @var array holds the payload entries of the jwt content
	 */
	protected $payload = [];

	/**
	 * Returns whether or not the token is currently valid. This means a proper
	 * issues stamp and it is in a currently valid date range
	 *
	 * @return bool true if valid
	 */
	public function isValid()
	{
		$issuedAtValid = $this->getIssuedAt() !== null ? $this->getIssuedAt() <= time() : true;
		return $issuedAtValid && !$this->isExpired() && !$this->isNotYetValid();
	}

	/**
	 * Returns whether or not the token is expired
	 *
	 * @return bool true if expired
	 */
	public function isExpired()
	{
		return $this->getExpiresAt() !== null ? $this->getExpiresAt() < time() : false;
	}

	/**
	 * Returns whether or not the token is not yet valid
	 *
	 * @return bool true if not yet valid
	 */
	public function isNotYetValid()
	{
		return $this->getNotValidBefore() !== null ? $this->getNotValidBefore() > time() : false;
	}

	/**
	 * Returns the whole payload as is
	 *
	 * @return array the payload of the token
	 */
	public function getPayload()
	{
		return $this->payload;
	}

	/**
	 * Checks whether or not a certain payload entry is set
	 *
	 * @param string $key they key to look up
	 * @return bool true if entry exists
	 */
	public function hasPayloadEntry($key)
	{
		return isset($this->payload[$key]);
	}

	/**
	 * Returns the contents of a payload entry or null if not found
	 *
	 * @param string $key the key to look up
	 * @return mixed|null either the value or null if the key does not exist
	 */
	public function getPayloadEntry($key)
	{
		return $this->hasPayloadEntry($key) ? $this->payload[$key] : null;
	}

	/**
	 * Returns the contents of the issuer payload field (`iss`)
	 *
	 * @return mixed|null either the issuer or null if not specified
	 * @see https://tools.ietf.org/html/rfc7519#page-9
	 */
	public function getIssuer()
	{
		return $this->getPayloadEntry('iss');
	}

	/**
	 * Returns the contents of the subject payload field (`sub`)
	 *
	 * @return mixed|null either the subject or null if not specified
	 * @see https://tools.ietf.org/html/rfc7519#page-9
	 */
	public function getSubject()
	{
		return $this->getPayloadEntry('sub');
	}

	/**
	 * Returns the contents of the audience payload field (`aud`)
	 *
	 * @return mixed|null either the audience or null if not specified
	 * @see https://tools.ietf.org/html/rfc7519#page-9
	 */
	public function getAudience()
	{
		return $this->getPayloadEntry('aud');
	}

	/**
	 * Returns the contents of the expires at payload field (`exp`)
	 *
	 * @return integer|null either the expires at timestamp or null if not specified
	 * @see https://tools.ietf.org/html/rfc7519#page-9
	 */
	public function getExpiresAt()
	{
		$val = $this->getPayloadEntry('exp');
		return $val !== null ? intval($val) : null;
	}

	/**
	 * Returns the contents of the not valid before payload field (`nbf`)
	 *
	 * @return integer|null either the not valid before timestamp or null if not specified
	 * @see https://tools.ietf.org/html/rfc7519#page-10
	 */
	public function getNotValidBefore()
	{
		$val = $this->getPayloadEntry('nbf');
		return $val !== null ? intval($val) : null;
	}

	/**
	 * Returns the contents of the issued at payload field (`iat`)
	 *
	 * @return integer|null either the issued at timestamp or null if not specified
	 * @see https://tools.ietf.org/html/rfc7519#page-10
	 */
	public function getIssuedAt()
	{
		$val = $this->getPayloadEntry('iat');
		return $val !== null ? intval($val) : null;
	}

	/**
	 * Returns the contents of the jti payload field (`jti`)
	 *
	 * @return mixed|null either the jti value or null if not specified
	 * @see https://tools.ietf.org/html/rfc7519#page-10
	 */
	public function getJti()
	{
		return $this->getPayloadEntry('jti');
	}

}
