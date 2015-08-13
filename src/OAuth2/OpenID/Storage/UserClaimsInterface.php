<?php

namespace OAuth2\OpenID\Storage;

/**
 * Implement this interface to specify where the OAuth2 Server
 * should retrieve user claims for the OpenID Connect id_token.
 */
interface UserClaimsInterface
{
    // valid scope values to pass into the user claims API call
    const VALID_CLAIMS = 'profile email address phone e_assets d_assets';

    // fields returned for the claims above
    const PROFILE_CLAIM_VALUES = 'name family_name given_name middle_name nickname preferred_username profile picture website gender birthdate zoneinfo locale updated_at';
    const EMAIL_CLAIM_VALUES = 'email email_verified';
    const ADDRESS_CLAIM_VALUES = 'formatted street_address locality region postal_code country';
    const PHONE_CLAIM_VALUES = 'phone_number phone_number_verified';
    const E_ASSETS_CLAIM_VALUES = 'userid teamid membership membership_exires_at user_type active solve_membership_error';
    const D_ASSETS_CLAIM_VALUES = 'userid teamid membership membership_exires_at user_type active solve_membership_error';

    /**
     * Return claims about the provided user id.
     *
     * Groups of claims are returned based on the requested scopes. No group
     * is required, and no claim is required.
     *
     * @param $user_id
     * The id of the user for which claims should be returned.
     * @param $scope
     * The requested scope.
     * Scopes with matching claims: profile, email, address, phone.
     *
     * @return
     * An array in the claim => value format.
     *
     * @see http://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
     */
    public function getUserClaims($user_id, $scope);
}
