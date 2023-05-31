from django.conf import settings
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
)
from webauthn import (
    verify_authentication_response as webauthn_verify_authentication_response,
)
from webauthn import (
    verify_registration_response as webauthn_verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticationCredential,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    RegistrationCredential,
    UserVerificationRequirement,
)


def make_credential_creation_options(user, rp, excluded_credential_ids, challenge=None):
    """
    Builds the options object needed for `navigator.credentials.create`
    to create a public key credential and register a new authenticator
    :param user: a PublicKeyCredentialUserEntity instance representing the user 4
     will register a new authenticator
    :param rp: a PublicKeyCredentialRpEntity instance representing the Relying Party
    :param excluded_credential_ids: a list of credential ids of authenticators already
    registered by this user
    :param challenge: the challenge that will be compared to the one returned in the
    client's response
    :return: a JSON-serialized PublicKeyCredentialCreationOptions object
    """
    exclude_credentials = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(credential_id))
        for credential_id in excluded_credential_ids
    ]
    if challenge:
        challenge = base64url_to_bytes(challenge)

    authenticator_attachment = None
    if settings.TWO_FACTOR_WEBAUTHN_AUTHENTICATOR_ATTACHMENT:
        authenticator_attachment = AuthenticatorAttachment(
            settings.TWO_FACTOR_WEBAUTHN_AUTHENTICATOR_ATTACHMENT
        )

    creation_options = generate_registration_options(
        rp_id=rp.id,
        rp_name=rp.name,
        user_id=user.id.decode("utf-8"),
        user_name=user.name,
        user_display_name=user.display_name,
        challenge=challenge,
        attestation=AttestationConveyancePreference(
            settings.TWO_FACTOR_WEBAUTHN_ATTESTATION_CONVEYANCE
        ),
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=authenticator_attachment,
            user_verification=UserVerificationRequirement(
                settings.TWO_FACTOR_WEBAUTHN_UV_REQUIREMENT
            ),
        ),
        exclude_credentials=exclude_credentials,
    )
    return options_to_json(creation_options), bytes_to_base64url(
        creation_options.challenge
    )


def verify_registration_response(
    expected_rp_id, expected_origin, expected_challenge, registration_token
):
    """
    Validate the result of `navigator.credentials.create`
    :param expected_rp_id: expected ID of the Relying Party
    :param expected_origin: the base domain with protocol on which the
    registration ceremony took place
    :param expected_challenge: the challenge returned by
    make_credential_creation_options
    :param registration_token: a serialized RegistrationCredential object
    :return: a tuple with the credential public key, id and current sign count
    """
    verified_registration = webauthn_verify_registration_response(
        credential=RegistrationCredential.parse_raw(registration_token),
        expected_challenge=base64url_to_bytes(expected_challenge),
        expected_origin=expected_origin,
        expected_rp_id=expected_rp_id,
        require_user_verification=settings.TWO_FACTOR_WEBAUTHN_UV_REQUIREMENT
        == UserVerificationRequirement.REQUIRED,
        pem_root_certs_bytes_by_fmt=settings.TWO_FACTOR_WEBAUTHN_PEM_ROOT_CERTS_BYTES_BY_FMT,  # noqa
    )

    return (
        bytes_to_base64url(verified_registration.credential_public_key),
        bytes_to_base64url(verified_registration.credential_id),
        verified_registration.sign_count,
    )


def make_credential_request_options(rp, allowed_credential_ids, challenge=None):
    """
    Build the options object needed for `navigator.credentials.get`
    to get a credential identifying a user that logged in with a WebAuthn device
    :param relying_party: a PublicKeyCredentialRpEntity instance representing
    the Relying Party
    :param allowed_credential_ids: a list of credential ids of authenticators
    already registered by this user
    :param challenge: the challenge that will be compared to the one returned
    in the client's response
    :return: A JSON-serialized PublicKeyCredentialRequestOptions object
    """
    preferred_transports = None
    if settings.TWO_FACTOR_WEBAUTHN_PREFERRED_TRANSPORTS:
        preferred_transports = [
            AuthenticatorTransport(transport)
            for transport in settings.TWO_FACTOR_WEBAUTHN_PREFERRED_TRANSPORTS
        ]

    allow_credentials = [
        PublicKeyCredentialDescriptor(
            id=base64url_to_bytes(credential_id),
            transports=preferred_transports,
        )
        for credential_id in allowed_credential_ids
    ]
    if challenge:
        challenge = base64url_to_bytes(challenge)

    request_options = generate_authentication_options(
        rp_id=rp.id,
        challenge=challenge,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement(
            settings.TWO_FACTOR_WEBAUTHN_UV_REQUIREMENT
        ),
    )
    return options_to_json(request_options), bytes_to_base64url(
        request_options.challenge
    )


def verify_authentication_response(
    public_key,
    current_sign_count,
    expected_rp,
    expected_origin,
    expected_challenge,
    authentication_token,
):
    """
    Validate the result of `navigator.credentials.get`
    :public_key: the public key of the credential
    :current_sign_count: the current sign count of the credential
    :param expected_rp: the expected WebAuthn Relying Party information
    contained in the credential
    :param expected_origin: the base domain with protocol on which the
    authentication ceremony took place
    :param expected_challenge: the challenge returned by
    make_credential_request_options
    :param authentication_token: a serialized AuthenticationCredential object
    :return: the new sign count for the WebauthnDevice instance
    """
    verified_authentication = webauthn_verify_authentication_response(
        credential=AuthenticationCredential.parse_raw(authentication_token),
        expected_challenge=base64url_to_bytes(expected_challenge),
        expected_rp_id=expected_rp.id,
        expected_origin=expected_origin,
        credential_public_key=base64url_to_bytes(public_key),
        credential_current_sign_count=current_sign_count,
        require_user_verification=settings.TWO_FACTOR_WEBAUTHN_UV_REQUIREMENT
        == UserVerificationRequirement.REQUIRED,
    )

    return verified_authentication.new_sign_count
