<?php

namespace OAuth2\OpenID\Storage;

interface DisplayCodeInterface
{
    public function getDisplayCode($display_code);

    public function setDisplayCode($display_code, $expires, $refreshToken, $name);
}
