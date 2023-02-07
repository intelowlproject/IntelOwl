import { PASSWORD_REGEX, EMAIL_REGEX } from "../../../constants";
import { RECAPTCHA_SITEKEY } from "../../../constants/environment";

export function PasswordValidator(password, confirmPassword) {
  const errors = {};
  // password fields
  if (!password) {
    errors.password = "Required";
  } else if (password.length < 12) {
    errors.password = "Must be 12 characters or more";
  } else if (!PASSWORD_REGEX.test(password)) {
    errors.password =
      "The password is entirely numeric or contains special characters";
  }
  if (!confirmPassword) {
    errors.confirmPassword = "Required";
  } else if (confirmPassword.length < 12) {
    errors.confirmPassword = "Must be 12 characters or more";
  }
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
