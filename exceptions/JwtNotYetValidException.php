<?php
namespace asinfotrack\yii2\jwt\exceptions;

/**
 * Exception used when a token contains valid data, but is not yet valid according to the timestamp provided
 *
 * @author Pascal Mueller, AS infotrack AG
 * @link http://www.asinfotrack.ch
 * @license AS infotrack AG license / MIT, see provided license file
 */
class JwtNotYetValidException extends \asinfotrack\yii2\jwt\exceptions\JwtException
{

}
