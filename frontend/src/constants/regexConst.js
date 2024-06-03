export const UUID_REGEX =
  /^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$/i;

// OBSERVABLES
// ip regex is valid for both IPv4 and IPv6
export const IP_REGEX =
  /^(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}::|(?:(?:[0-9a-fA-F]{1,4}:){1,6}:)(?::[0-9a-fA-F]{1,4}){1,2}))$/;
export const DOMAIN_REGEX = /^(?:[\w-]{1,63}\.)+[\w-]{2,63}$/;
export const URL_REGEX = /^.{2,20}:\/\/.+$/;
export const HASH_REGEX = /^[a-zA-Z0-9]{32,}$/;
export const PHONE_REGEX = /^\+[1-9]\d{1,14}$/;

export const EMAIL_REGEX = /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}$/i;
export const PASSWORD_REGEX = /^(?=.*[a-zA-Z])[a-zA-Z0-9]{12,}$/i;
