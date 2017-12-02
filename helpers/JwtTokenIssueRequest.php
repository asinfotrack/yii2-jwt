<?php
namespace asinfotrack\yii2\jwt\helpers;

use Yii;
use yii\base\InvalidCallException;

/**
 * Class used to prepare data which should get encoded in a token
 *
 * @author Pascal Mueller, AS infotrack AG
 * @link http://www.asinfotrack.ch
 * @license AS infotrack AG license / MIT, see provided license file
 */
class JwtTokenIssueRequest extends \asinfotrack\yii2\jwt\helpers\JwtTokenContentBase
{

	/**
	 * @var bool whether or not this issue request is locked
	 */
	protected $isLocked = false;

	/**
	 * Locks this content after it was used to create a jwt token
	 */
	public function lock()
	{
		$this->isLocked = true;
	}

	/**
	 * Adds a payload entry to the issue request
	 *
	 * @param string $key the key to add
	 * @param mixed $value the value
	 *
	 * @return bool true if set or false if overwrite was tried and not allowed
	 */
	public function setPayloadEntry($key, $value)
	{
		if ($this->isLocked) {
			$msg = Yii::t('app', 'This creation content is locked already and can not be modified');
			throw new InvalidCallException($msg);
		}

		$this->payload[$key] = $value;
		return true;
	}

	/**
	 * Sets multiple payload entries at once
	 *
	 * @param array $entries array indexed by entry key
	 */
	public function setPayloadEntries(array $entries)
	{
		foreach ($entries as $key=>$data) {
			$this->setPayloadEntry($key, $data);
		}
	}

	/**
	 * Set the issuer payload entry (`iss`)
	 *
	 * @param string $issuer the issuer to set
	 * @see https://tools.ietf.org/html/rfc7519#page-9
	 */
	public function setIssuer($issuer)
	{
		$this->setPayloadEntry('iss', $issuer);
	}

	/**
	 * Set the subject payload entry (`sub`)
	 *
	 * @param string $subject the subject to set
	 * @see https://tools.ietf.org/html/rfc7519#page-9
	 */
	public function setSubject($subject)
	{
		$this->setPayloadEntry('sub', $subject);
	}

	/**
	 * Set the audience payload entry (`aud`)
	 *
	 * @param string $audience the audience to set
	 * @see https://tools.ietf.org/html/rfc7519#page-9
	 */
	public function setAudience($audience)
	{
		$this->setPayloadEntry('aud', $audience);
	}

	/**
	 * Set the expires at payload entry (`exp`), which is responsible to
	 * determine if a token is still valid at a certain time.
	 *
	 * @param integer $timestamp the timestamp to set
	 * @see https://tools.ietf.org/html/rfc7519#page-9
	 */
	public function setExpiresAt($timestamp)
	{
		$this->setPayloadEntry('exp', $timestamp);
	}

	/**
	 * Set the not valid before payload entry (`nbf`), which decides from which
	 * point onwards a token is valid
	 *
	 * @param integer $timestamp the timestamp from which the token is valid
	 * @see https://tools.ietf.org/html/rfc7519#page-10
	 */
	public function setNotValidBefore($timestamp)
	{
		$this->setPayloadEntry('nbf', $timestamp);
	}

	/**
	 * Set the issued at payload entry (`iat`) which shows, when a token was created
	 * and also prevents usage before that time.
	 *
	 * @param integer $timestamp the timestamp the token was created
	 * @see https://tools.ietf.org/html/rfc7519#page-10
	 */
	public function setIssuedAt($timestamp)
	{
		$this->setPayloadEntry('iat', $timestamp);
	}

	/**
	 * Set the jti payload entry (`jti`). This entry holds the id of the item
	 * this token is assigned to. In a regular scenario this would be the user id.
	 *
	 * One has to make sure, that the jti is unique within the scope of the application
	 * and does not identify other subjects, than the one this token was generated for!
	 *
	 * @param string $jti the jti to set
	 * @see https://tools.ietf.org/html/rfc7519#page-10
	 */
	public function setJti($jti)
	{
		$this->setPayloadEntry('jti', $jti);
	}

}
