<?php
namespace asinfotrack\yii2\jwt\traits;

use Yii;
use yii\base\InvalidCallException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use asinfotrack\yii2\jwt\helpers\JwtTokenDecodingResult;
use asinfotrack\yii2\jwt\helpers\JwtTokenIssueRequest;
use asinfotrack\yii2\jwt\exceptions\JwtNotYetValidException;
use asinfotrack\yii2\jwt\exceptions\JwtException;
use asinfotrack\yii2\jwt\exceptions\JwtSignatureException;

/**
 * The trait adds basic functionality to work with JSON web tokens to any class desired. It
 * is not coupled to any type of class and can therefore be used in a very flexible way.
 *
 * The methods provided can be used to create and decrypt tokens. However, the persistence
 * has to be implemented by yourself. This was left aside to prevent coupling to model
 * classes.
 *
 * Override `getAllowedAlgorithms()` if you want to specify your own set of allowed algorithms.
 * Override `addDefaultPayload()` if you want your own default payload defined. This can also
 * be achieved easily if you set `$addDefaultPayloadCallback` to a valid callable, which will
 * then be called instead of the method mentioned before.
 *
 * @author Pascal Mueller, AS infotrack AG
 * @link http://www.asinfotrack.ch
 * @license AS infotrack AG license / MIT, see provided license file
 */
trait JwtTokenTrait {

	/**
	 * @var callable an optional callable which can be used to add default payload data to the tokens
	 * while they are being created. If not set, the static method `addDefaultPayload()` of this trait
	 * will be called.
	 *
	 * The callback should have the signature `function ($issueRequest, $defaultLifespanSeconds)` and
	 * return the same object after performing the modifications.
	 */
	public $addDefaultPayloadCallback;

	/**
	 * @var int the default lifespan of the tokens generated (defaults to six months). Set this to null
	 * if tokens will never expire.
	 */
	public $defaultJwtTokenLifespanSeconds = 86400 * 30 * 6;

	/**
	 * Creates a jwt token from an issue request object with the array specified. The model id
	 * must be provided and will be saved in the jti payload data field. Usually this is the id
	 * of the user, this token is created for.
	 *
	 * If you use asymmetric keys, use the private key as the secret to create the token.
	 *
	 * @param mixed $modelId the id of the model this token is created for
	 * @param string $secret the secret used to sign the token (if asymmetric: private key)
	 * @param \asinfotrack\yii2\jwt\helpers\JwtTokenIssueRequest $issueRequest the issue request
	 * containing the data. if none specified, an empty one will be created.
	 * @param string $algorithm the algorithm to use (defaults to HS256)
	 * @return string the token
	 * @throws \yii\base\InvalidCallException when an algorithm was requested, which is not allowed
	 */
	public function createJwtToken($modelId, $secret, $issueRequest=null, $algorithm='HS256')
	{
		//validate algorithm
		if (!in_array($algorithm, static::getAllowedAlgorithms())) {
			$msg = Yii::t('app', 'The algorithm `{$alg}` is not allowed', ['alg'=>$algorithm]);
			throw new InvalidCallException($msg);
		}

		//create empty issue request if none specified
		if ($issueRequest === null) $issueRequest = new JwtTokenIssueRequest();

		//add default payload
		if (is_callable($this->addDefaultPayloadCallback)) {
			$issueRequest = call_user_func($this->addDefaultPayloadCallback, $issueRequest, $this->defaultJwtTokenLifespanSeconds);
		} else {
			$issueRequest = static::addDefaultPayload($issueRequest, $this->defaultJwtTokenLifespanSeconds);
		}

		//set jti to id of model this token is generated for and other important payload entries
		$issueRequest->setJti($modelId);
		$issueRequest->setIssuedAt(time());

		//create and return the generated token
		return JWT::encode($issueRequest->getPayload(), $secret, $algorithm);
	}

	/**
	 * Decodes the contents of a token and creates a token decoding result from it.
	 * The exception behavior can be specified with the last two params. The model id
	 * (usually the user id ) can be retrieved from the jti payload data field as per spec.
	 *
	 * If you use asymmetric keys, use the public key as the secret to decode the token.
	 *
	 * @param string $token the raw token as received
	 * @param string $secret the secret which was used to sign the token (if asymmetric: public key)
	 * @param bool $throwExceptionWhenExpired whether or not to throw an exception when the token is valid but expired
	 * @param bool $throwExceptionWhenNotYetValid whether or not to throw an exception when the token has valid contents but is not yet valid
	 * @return \asinfotrack\yii2\jwt\helpers\JwtTokenDecodingResult the result containing all the data
	 * @throws \asinfotrack\yii2\jwt\exceptions\JwtException when the contents of the token are not valid
	 * @throws \asinfotrack\yii2\jwt\exceptions\JwtNotYetValidException when desired an the token is not yet valid
	 * @throws \asinfotrack\yii2\jwt\exceptions\JwtSignatureException when the signature in the token is not valid
	 */
	public function decodeJwtToken($token, $secret, $throwExceptionWhenExpired=false, $throwExceptionWhenNotYetValid=false)
	{
		try {
			//try decoding the token
			$payload = JWT::decode($token, $secret, static::getAllowedAlgorithms());
			//decoding was ok...get the header as well
			list($headBase64) = explode('.', $token);
			$header = JWT::jsonDecode(JWT::urlsafeB64Decode($headBase64));
		} catch (SignatureInvalidException $e) {
			//the signature was not valid
			$msg = Yii::t('app', 'Jwt token signature is invalid');
			throw new JwtSignatureException($msg);
		} catch (\UnexpectedValueException $e) {
			//the rest of the exceptions are all Unexpected value exceptions
			if ($e instanceof BeforeValidException || $e instanceof ExpiredException) {
				//handle the before valid and expired specially
				if ($e instanceof BeforeValidException && $throwExceptionWhenNotYetValid) {
					$msg = Yii::t('app', 'The token is not yet valid');
					throw new JwtNotYetValidException($msg);
				}
				if ($e instanceof ExpiredException && $throwExceptionWhenExpired) {
					$msg = Yii::t('app', 'The token is expired');
					throw new JwtNotYetValidException($msg);
				}

				//fetch payload and header as the decoding was ok but the token was considered invalid
				list($headBase64, $bodyBase64) = explode('.', $token);
				$header = JWT::jsonDecode(JWT::urlsafeB64Decode($headBase64));
				$payload = JWT::jsonDecode(JWT::urlsafeB64Decode($bodyBase64));
			} else {
				//other error which we throw now
				throw new JwtException(Yii::t('app', $e->getMessage()));
			}
		}

		return new JwtTokenDecodingResult(static::convertToArray($header), static::convertToArray($payload));
	}

	/**
	 * Returns an array of allowed algorithms. By default it returns the ones specified by
	 * the jwt library.
	 *
	 * Override this method to return your own list of algorithms!
	 *
	 * @return string[] list of allowed algorithms
	 * @see \Firebase\JWT\JWT::$supported_algs
	 */
	public static function getAllowedAlgorithms()
	{
		return array_keys(JWT::$supported_algs);
	}

	/**
	 * Adds the default payload to the token when no callback is specified
	 *
	 * @param \asinfotrack\yii2\jwt\helpers\JwtTokenIssueRequest $issueRequest the issue request
	 * @return \asinfotrack\yii2\jwt\helpers\JwtTokenIssueRequest the modified token request
	 */
	protected static function addDefaultPayload($issueRequest, $defaultLifespanSeconds=null)
	{
		$issueRequest->setNotValidBefore(time());

		if (!empty(Yii::$app->name)) $issueRequest->setSubject(Yii::$app->name);
		if (Yii::$app instanceof \yii\web\Application) $issueRequest->setIssuer(Yii::$app->request->hostInfo);
		if ($defaultLifespanSeconds !== null && !$issueRequest->hasPayloadEntry('ext')) {
			$issueRequest->setExpiresAt(time() + $defaultLifespanSeconds);
		}

		return $issueRequest;
	}

	/**
	 * Converts a param to an array if necessary. If an array is provided, it is left
	 * untouched.
	 *
	 * @param array|object|null $param the param to convert
	 * @param bool $recursive if true, all sub properties will be converted recursively as well
	 * @param int $depth the current recursion depth
	 * @return array the converted array
	 */
	protected static function convertToArray($param, $recursive=true, $depth=0)
	{
		//handle special cases
		if ($param === null && $depth === 0) return [];

		//convert (recursively, if necessary)
		if (is_object($param)) $param = (array) $param;
		if ($recursive && is_array($param)) {
			foreach ($param as $key=>&$val) {
				$val = static::convertToArray($val, $recursive, $depth+1);
			}
		}
		return $param;
	}

}
