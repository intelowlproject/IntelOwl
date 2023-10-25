export const EMAIL_REGEX = /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}$/i;
export const URL_REGEX = "(www.|http://|https://).*";
export const UUID_REGEX =
  /^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$/i;
export const PASSWORD_REGEX = /^(?=.*[a-zA-Z])[a-zA-Z0-9]{12,}$/i;
