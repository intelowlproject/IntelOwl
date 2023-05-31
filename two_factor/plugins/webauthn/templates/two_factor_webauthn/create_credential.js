let credentialCreationOptions = {{ credential_creation_options|safe }};

credentialCreationOptions.challenge = b64str2ab(credentialCreationOptions.challenge);
for (let i = 0; i < credentialCreationOptions.excludeCredentials.length; i++) {
    credentialCreationOptions.excludeCredentials[i].id = b64str2ab(credentialCreationOptions.excludeCredentials[i].id);
}
credentialCreationOptions.user.id = b64str2ab(credentialCreationOptions.user.id);

navigator.credentials.create({
    publicKey: credentialCreationOptions
}).then((attestationCredential) => {
    let response = attestationCredential.response,
        serializableAttestationCredential = {
            id: attestationCredential.id,
            rawId: ab2str(attestationCredential.rawId),
            response: {
                clientDataJSON: ab2str(response.clientDataJSON),
                attestationObject: ab2str(response.attestationObject),
            },
            type: attestationCredential.type,
        },
        tokenField = document.querySelector('[name=webauthn-token]'),
        form = document.forms[0];

    tokenField.value = JSON.stringify(serializableAttestationCredential);
    form.submit();

}, (reason) => {
    console.debug("Registration error: ", reason);

    let errMsgNode = document.createElement("p"),
        tokenField = document.querySelector('#id_webauthn-token');

    errMsgNode.setAttribute("class", "text-danger");
    errMsgNode.appendChild(document.createTextNode(reason));
    tokenField.parentNode.insertBefore(errMsgNode, tokenField.nextSibling);
});
