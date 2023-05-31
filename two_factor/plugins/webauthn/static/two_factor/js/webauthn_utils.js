function ab2str(buf) {
    if (buf == null) {
        return null;
    };

    return btoa(String.fromCharCode.apply(null, new Uint8Array(buf)));
}

function b64str2ab(b64_encoded_string) {
    if (b64_encoded_string == null) {
        return null;
    };

    let string = atob(b64_encoded_string.replace(/_/g, '/').replace(/-/g, '+')),
        buf = new ArrayBuffer(string.length),
        bufView = new Uint8Array(buf);
    for (var i = 0, strLen = string.length; i < strLen; i++) {
        bufView[i] = string.charCodeAt(i);
    }
    return buf;
}
