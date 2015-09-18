<?php

namespace OAuth2\OpenID\GrantType;

use OAuth2\GrantType\GrantTypeInterface;
use OAuth2\ResponseType\AccessTokenInterface;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;
use OAuth2\OpenID\Storage\DisplayCodeInterface;

/**
 *
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
class DisplayCode implements GrantTypeInterface
{
    protected $displayUserInfo;
    protected $storage;

    /**
     * @param \OAuth2\Storage\UserCredentialsInterface $storage REQUIRED Storage class for retrieving user credentials information
     */
    public function __construct(DisplayCodeInterface $storage)
    {
        $this->storage = $storage;
    }

    public function getQuerystringIdentifier()
    {
        return 'display_code';
    }

    public function validateRequest(RequestInterface $request, ResponseInterface $response)
    {
        if (!$request->request("display_code")) {
            $response->setError(400, 'invalid_request', 'Missing parameter: "display_code" required');

            return null;
        }

        $displayUserInfo = $this->storage->getDisplayCode($request->request("display_code"));
        if (!$displayUserInfo) {
            $response->setError(401, 'invalid_grant', 'Invalid display_code');

            return null;
        }

        $this->displayUserInfo = $displayUserInfo;

        return true;
    }

    public function getClientId()
    {
        return null;
    }

    public function getUserId()
    {
        return $this->displayUserInfo['id'];
    }

    public function getScope()
    {
        return null;
    }

    public function createAccessToken(AccessTokenInterface $accessToken, $client_id, $user_id, $scope)
    {
        return $accessToken->createAccessToken($client_id, $user_id, $scope);
    }
}
