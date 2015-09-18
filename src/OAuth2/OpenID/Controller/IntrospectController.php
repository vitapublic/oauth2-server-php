<?php

namespace OAuth2\OpenID\Controller;

use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;
use OAuth2\ClientAssertionType\HttpBasic;
use OAuth2\Storage\AccessTokenInterface;
use OAuth2\Storage\ClientInterface;

class IntrospectController implements IntrospectControllerInterface
{
    protected $config;
    protected $tokenStorage;
    protected $clientStorage;
    protected $clientAssertionType;

    public function __construct(AccessTokenInterface $tokenStorage, ClientInterface $clientStorage, HttpBasic $clientAssertionType, array $config = array())
    {
        $this->config = array_merge(
            array(
                'token_param_name'    => 'token',
                'resource_param_name' => 'resource_id',
            ),
            $config
        );

        $this->tokenStorage = $tokenStorage;
        $this->clientStorage = $clientStorage;
        $this->clientAssertionType = $clientAssertionType;
    }

    public function handleIntrospectRequest(RequestInterface $request, ResponseInterface $response)
    {
        // validate client credentials in AUTHORIZATION header
        if (!$this->clientAssertionType->validateRequest($request, $response)) {
            return false;
        }

        // validate token
        $token_param = $request->request($this->config['token_param_name']);
        if (!$token = $this->tokenStorage->getAccessToken($token_param)) {
            $response->setError(401, 'invalid_token', 'The access token provided is invalid');
            return false;
        } elseif (!isset($token["expires"]) || !isset($token["client_id"])) {
            $response->setError(401, 'malformed_token', 'Malformed token (missing "expires")');
            return false;
        } elseif (time() > $token["expires"]) {
            $response->setError(401, 'expired_token', 'The access token provided has expired');
            return false;
        }

        // check for resource ID parameter
        $resource_id = $request->request($this->config['resource_param_name']);
        if (empty($resource_id)) {
            $response->setError(400, 'invalid_request', 'Missing resource ID');
            return false;
        }

        // @todo: validate resource
//        if (invalid) {
//            $response->addParameters(
//                array(
//                    'active' => false,
//                )
//            );
//            return true;
//        }

        //get resource sub and aud
        $sub = '<internal-resource-id>';
        $aud = $resource_id;

        $response->addParameters(
            array(
                'active'          => true,
                'client_id'       => $token['client_id'],
                'user_id'         => $token['user_id'],
                'scope'           => $token['scope'],
                'sub'             => $sub,
                'aud'             => $aud,
                'iss'             => $this->config['issuer'],
                'exp'             => $token['expires'],
                'iat'             => $token['expires'] - $this->config['id_lifetime'],
            )
        );

        return true;
    }
}
