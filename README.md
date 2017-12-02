# Yii2-jwt
Yii2-jwt is a set of functionality to work with JSON Web Tokens. It is a wrapper around the JWT extension
`firebase/php-jwt` which can be attached to any class as a trait. The data of tokens is encapsulated in
helper classes and represented as arrays, as it is usual within Yii2-applications.

Also check out the [repository of the firebase jwt extension](https://github.com/firebase/php-jwt).

## Installation

### Basic installation

The preferred way to install this extension is through [composer](http://getcomposer.org/download/).

Either run

```bash
$ composer require asinfotrack/yii2-jwt
```

or add

```
"asinfotrack/yii2-article": "~0.8.0"
```

to the `require` section of your `composer.json` file.

## Usage

Simply add the `JwtTokenTrait` to any class you wish to create tokens for. Usually this is a user class.

```php
class User extends \yii\db\ActiveRecorde implements \yii\web\IdentityInterface
{
	
	//...
	
	use JwtTokenTrait;
	
	//...
	
	/**
	 * @inheritdoc
	 */
	public static function findIdentityByAccessToken($token, $type=null)
	{
		/* @var $result \asinfotrack\yii2\jwt\helpers\JwtTokenDecodingResult */
	
		try {
			//try decoding the token
			$result = $this->decodeJwtToken($token, Yii::$app->params['myJwtTokenSecret'], true, true);
		} catch (JwtException $e) {
			//check if token is valid but expired
			if ($e instanceof \asinfotrack\yii2\jwt\exceptions\JwtExpiredException) {
				//delete expired token from db
			}
			
			//return null to signal user could not be found
			return null;
		}
		
		//token was valid so we can extract the id
		$modelId = $result->getJti();
		
		//return the user model or null if not found
		return User::findOne($modelId);
	}
	
	//...
	
	/**
	 * Create a token for the current user model instance. You might want to persist
	 * the result in a token table to keep track of the tokens created.
	 *
	 * @return string the created token
	 */
	protected function createTokenForUser()
	{
		/* @var $request \asinfotrack\yii2\jwt\helpers\JwtTokenIssueRequest */
	
		//optional request if additional data is required (eg user roles)
		$userRoles = array_keys(Yii::$app->authManager->getRolesByUser($this->id));
		$request = new JwtIssueRequest();
		$request->setPayloadEntry('roles', $userRoles);
		
		return $this->createJwtToken($this->id, Yii::$app->params['myJwtTokenSecret'], $request);
	}
	
	//...
	
}
``` 

## Changelog

###### [v0.8.0] (work in progress)
- main classes in a stable condition
- further features will be added in a backwards-compatible way from here on
- all breaking changes will lead to a new minor version.
