let credentialRequestOptions = {{ credential_request_options|safe }};

credentialRequestOptions.challenge = b64str2ab(credentialRequestOptions.challenge);
for (let i = 0; i < credentialRequestOptions.allowCredentials.length; i++) {
    credentialRequestOptions.allowCredentials[i].id = b64str2ab(credentialRequestOptions.allowCredentials[i].id);
}

navigator.credentials.get({
    publicKey: credentialRequestOptions
}).then((assertionCredential) => {
    let response = assertionCredential.response,
        serializableAssertionCredential = {
            id: assertionCredential.id,
            rawId: ab2str(assertionCredential.rawId),
            response: {
                clientDataJSON: ab2str(response.clientDataJSON),
                authenticatorData: ab2str(response.authenticatorData),
                signature: ab2str(response.signature),
                userHandle: ab2str(response.userHandle),
            },
            type: assertionCredential.type,
        },
        tokenField = document.querySelector('[name=token-otp_token]'),
        authenticationTokenForm = document.forms[0];

    tokenField.value = JSON.stringify(serializableAssertionCredential);
    authenticationTokenForm.submit();
}, (reason) => {
    console.debug("Authentication error: ", reason);
    
    let errMsgNode = document.createElement("p"),
        tokenField = document.querySelector('[name=token-otp_token]');

    errMsgNode.setAttribute("class", "text-danger");
    errMsgNode.appendChild(document.createTextNode(reason));
    tokenField.parentNode.insertBefore(errMsgNode, tokenField.nextSibling);
});
