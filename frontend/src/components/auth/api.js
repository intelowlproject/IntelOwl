import axios from "axios";

import { addToast } from "@certego/certego-ui";

import { AUTH_BASE_URI } from "../../constants/api";

export async function registerUser(body) {
  try {
    const resp = await axios.post(`${AUTH_BASE_URI}/register`, body);
    return resp;
  } catch (err) {
    addToast("Registration failed!", err.parsedMsg, "danger", true);
    return Promise.reject(err);
  }
}

export async function verifyEmail(body) {
  try {
    const resp = await axios.post(`${AUTH_BASE_URI}/verify-email`, body);
    addToast(
      "Your email has been succesfully verified!",
      null,
      "success",
      true
    );
    return resp;
  } catch (err) {
    addToast("Email verification failed!", err.parsedMsg, "danger", true);
    return Promise.reject(err);
  }
}

export async function resendVerificationMail(body) {
  try {
    const resp = await axios.post(`${AUTH_BASE_URI}/resend-verification`, body);
    addToast("Verification email sent!", null, "success");
    return resp;
  } catch (err) {
    addToast("Failed to send email!", err.parsedMsg, "danger", true);
    return Promise.reject(err);
  }
}

export async function requestPasswordReset(body) {
  try {
    const resp = await axios.post(
      `${AUTH_BASE_URI}/request-password-reset`,
      body
    );
    addToast("Email sent!", null, "success");
    return resp;
  } catch (err) {
    addToast("Failed to send email!", err.parsedMsg, "danger", true);
    return null;
  }
}

export async function resetPassword(body) {
  try {
    const resp = await axios.post(`${AUTH_BASE_URI}/reset-password`, body);
    addToast("Password reset successfully!", null, "success", true);
    return resp;
  } catch (err) {
    addToast("Password reset failed!", err.parsedMsg, "danger", true);
    return Promise.reject(err);
  }
}

export async function checkConfiguration(body) {
  try {
    const resp = await axios.get(`${AUTH_BASE_URI}/configuration`, body);
    return resp;
  } catch (err) {
    return Promise.reject(err);
  }
}
