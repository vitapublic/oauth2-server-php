<?php

namespace OAuth2\OpenID\Controller;

use OAuth2\Controller\TokenController as BaseTokenController;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;
use OAuth2\ResponseType\AccessTokenInterface;
use OAuth2\ClientAssertionType\ClientAssertionTypeInterface;
use OAuth2\ScopeInterface;
use OAuth2\Storage\ClientInterface;

/**
 * @see OAuth2\Controller\TokenControllerInterface
 */
class TokenController extends BaseTokenController implements AuthorizeControllerInterface
{
    protected $responseTypes;

    public function __construct(AccessTokenInterface $accessToken, ClientInterface $clientStorage, array $grantTypes = array(), ClientAssertionTypeInterface $clientAssertionType = null, ScopeInterface $scopeUtil = null, array $responseTypes = array())
    {
        parent::__construct($accessToken, $clientStorage, $grantTypes, $clientAssertionType, $scopeUtil);

        $this->responseTypes = $responseTypes;
    }

    /**
     * Grant or deny a requested access token.
     * This would be called from the "/token" endpoint as defined in the spec.
     * You can call your endpoint whatever you want.
     *
     * @param $request - RequestInterface
     * @param $response - ResponseInterface
     *
     * Request object to grant access token
     *
     * @throws InvalidArgumentException
     * @throws LogicException
     *
     * @see http://tools.ietf.org/html/rfc6749#section-4
     * @see http://tools.ietf.org/html/rfc6749#section-10.6
     * @see http://tools.ietf.org/html/rfc6749#section-4.1.3
     *
     * @ingroup oauth2_section_4
     */
    public function grantAccessToken(RequestInterface $request, ResponseInterface $response)
    {
        if (!$params = parent::grantAccessToken($request, $response)) {
            return false;
        }

        // Generate an id token if needed.
        if ($this->needsIdToken($this->scopeUtil->getScopeFromRequest($request), $request->request('grant_type'))) {
            $userId = $this->grantTypes['password']->getUserId();
            $clientId = $this->grantTypes['password']->getClientId();
            try {
                $params['id_token'] = $this->responseTypes[self::RESPONSE_TYPE_ID_TOKEN]->createIdToken($clientId, $userId);
            } catch (\Exception $e) {
                var_dump($e);
                die();
            }
        }

        return $params;

    }

    /**
     * Returns whether the current request needs to generate an id token.
     *
     * ID Tokens are a part of the OpenID Connect specification, so this
     * method checks whether OpenID Connect is enabled in the server settings
     * and whether the openid scope was requested.
     *
     * @param $request_scope
     *  A space-separated string of scopes.
     *
     * @return
     *   TRUE if an id token is needed, FALSE otherwise.
     */
    public function needsIdToken($request_scope, $grant_type)
    {
        // see if the "openid" scope exists in the requested scope
        return $this->scopeUtil->checkScope('openid', $request_scope) && $grant_type !== 'refresh_token';
    }

    public function getScope()
    {
        return $this->scope;
    }
}
