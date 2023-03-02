import {
  PASSWORD_REGEX,
  EMAIL_REGEX,
  HACKER_MEME_STRING,
} from "../../../constants";
import { RECAPTCHA_SITEKEY } from "../../../constants/environment";

export function ComparePassword(password, confirmPassword) {
  const errors = {};
  if (
    password.length > 0 &&
    confirmPassword.length > 0 &&
    password !== confirmPassword
  ) {
    errors.password = "Passwords do not match.";
    errors.confirmPassword = "Passwords do not match.";
  }
  return errors;
}

export function PasswordValidator(password) {
  const errors = {};
  if (!password) {
    errors.password = "Required";
  } else if (password.length < 12) {
    errors.password = "Must be 12 characters or more";
  } else if (!PASSWORD_REGEX.test(password)) {
    errors.password =
      "The password is entirely numeric or contains special characters";
  }
  return errors;
}

export function UserFieldsValidator(field, value) {
  const errors = {};
  // text fields
  if (!value) {
    errors[field] = "Required";
  } else if (value.length > 15) {
    errors[field] = "Must be 15 characters or less";
  } else if (value.length < 4) {
    errors[field] = "Must be 4 characters or more";
  }
  return errors;
}

export function UsernameValidator(username) {
  const errors = UserFieldsValidator("username", username);
  if (
    ["administrator", "admin", "certego", "hacker"].indexOf(username) !== -1
  ) {
    errors.username = HACKER_MEME_STRING;
  }
  return errors;
}

export function ProfileValidator(field, value) {
  const errors = {};
  // text fields
  if (!value) {
    errors[field] = "Required";
  } else if (value.length > 30) {
    errors[field] = "Must be 30 characters or less";
  } else if (value.length < 3) {
    errors[field] = "Must be 3 characters or more";
  }
  return errors;
}

export function EmailValidator(email) {
  const errors = {};
  if (!email) {
    errors.email = "Required";
  } else if (!EMAIL_REGEX.test(email)) {
    errors.email = "Invalid email address";
  }
  return errors;
}

export function RecaptchaValidator(recaptcha) {
  const errors = {};
  if (recaptcha === "noKey" && RECAPTCHA_SITEKEY) {
    errors.recaptcha = "Required";
  }
  return errors;
}
