import axios from "axios";

import { addToast } from "@certego/certego-ui";

import { APIACCESS_BASE_URI, SESSIONS_BASE_URI } from "../../../constants/api";

// API Access

async function createNewToken() {
  try {
    const resp = await axios.post(APIACCESS_BASE_URI);
    addToast("Generated new API key for you!", null, "success", true);
    return resp;
  } catch (e) {
    addToast("Failed!", e.parsedMsg.toString(), "danger", true);
    return Promise.reject(e);
  }
}

async function deleteToken() {
  try {
    const resp = await axios.delete(APIACCESS_BASE_URI);
    addToast("API key was deleted!", null, "success", true);
    return resp;
  } catch (e) {
    addToast("Failed!", e.parsedMsg.toString(), "danger", true);
    return Promise.reject(e);
  }
}

// Sessions

async function deleteTokenById(id, clientName) {
  try {
    const resp = await axios.delete(`${SESSIONS_BASE_URI}/${id}`);
    addToast(`Revoked Session (${clientName}).`, null, "success", true, 6000);
    return resp;
  } catch (e) {
    addToast("Failed!", e.parsedMsg.toString(), "danger", true);
    return Promise.reject(e);
  }
}

export {
  APIACCESS_BASE_URI,
  SESSIONS_BASE_URI,
  createNewToken,
  deleteToken,
  deleteTokenById,
};
