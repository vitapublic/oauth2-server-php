<?php

/**
 * Vitapublic (http://www.vitapublic.de/)
 * 
 * PHP version 5.4
 * 
 * @category  
 * @package   
 * @author    Christian Bode <c.bode@vitapublic.de>
 * @copyright 2015 vitapublic GmbH (http://www.vitapublic.de/)
 * @license   Commercial
 * @link      http://www.vitapublic.de/
 */

namespace OAuth2\OpenID\ResponseType;

use OAuth2\Encryption\EncryptionInterface;
use OAuth2\Encryption\Jwt;
use OAuth2\OpenID\ResponseType\IdToken;
use OAuth2\OpenID\ResponseType\AwsTokenInterface;
use OAuth2\OpenID\Storage\UserClaimsInterface;
use OAuth2\Storage\UserCredentialsInterface;
use OAuth2\Storage\PublicKeyInterface;
/**
 * Class AwsToken ...
 * 
 * @category  
 * @package   
 * @author    Christian Bode <c.bode@vitapublic.de>
 * @copyright 2015 vitapublic GmbH (http://www.vitapublic.de/)
 * @license   Commercial
 * @link      http://www.vitapublic.de/
 */
class AwsToken extends IdToken implements AwsTokenInterface
{
    protected $userStorage;
    
    public function __construct(UserClaimsInterface $userClaimsStorage, PublicKeyInterface $publicKeyStorage, array $config = array(), EncryptionInterface $encryptionUtil = null, UserCredentialsInterface $userStorage)
    {
        $this->userClaimsStorage = $userClaimsStorage;
        $this->publicKeyStorage = $publicKeyStorage;
        $this->userStorage = $userStorage;
        
        if (is_null($encryptionUtil)) {
            $encryptionUtil = new Jwt();
        }
        $this->encryptionUtil = $encryptionUtil;

        if (!isset($config['issuer'])) {
            throw new \LogicException('config parameter "issuer" must be set');
        }
        $this->config = array_merge(array(
            'id_lifetime' => 3600,
        ), $config);
    }
    
    public function createAwsToken($client_id, $userInfo, $nonce = null, $userClaims = null, $access_token = null)
    {
        $userDetails               = $this->userStorage->getUserDetails($userInfo);
        list($user_id, $auth_time) = $this->getUserIdAndAuthTime($userInfo);
        
        $token = array(
            'iss'        => $this->config['issuer'],
            'sub'        => $user_id,
            'aud'        => $client_id,
            'iat'        => time(),
            'exp'        => time() + $this->config['id_lifetime'],
            'auth_time'  => $auth_time,
        );
        
        foreach ($this->config['aws_token_interceptor'] as $interceptorKey => $interceptorData) {
            if ($client_id === $interceptorKey) {
                $interceptor = new $interceptorData['class']();
                
                $token = array_merge(
                    $token,
                    $interceptor->intercept($client_id, $userDetails, $interceptorData['config'])
                );
            }
        }
        
        if ($nonce) {
            $token['nonce'] = $nonce;
        }

        if ($userClaims) {
            $token += $userClaims;
        }

        if ($access_token) {
            $token['at_hash'] = $this->createAtHash($access_token, $client_id);
        }

        return $this->encodeToken($token, $client_id);
    }
    
    public function getAuthorizeResponse($params, $userInfo = null)
    {
        return;
    }
}
