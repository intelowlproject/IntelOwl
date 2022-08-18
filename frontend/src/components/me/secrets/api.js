import axios from "axios";

import { addToast } from "@certego/certego-ui";

import { PLUGIN_SECRETS_URI } from "../../../constants/api";

async function createCustomConfig(data) {
  try {
    const resp = await axios.post(PLUGIN_SECRETS_URI, data);
    addToast("Data posted successfully", null, "success", true);
    return resp;
  } catch (e) {
    addToast("Failed!", e.parsedMsg.toString(), "danger", true);
    return Promise.reject(e);
  }
}

async function updateCustomConfig(data, id) {
  try {
    const resp = await axios.patch(`${PLUGIN_SECRETS_URI}/${id}`, data);
    addToast("Data updated successfully", null, "success", true);
    return resp;
  } catch (e) {
    addToast("Failed!", e.parsedMsg.toString(), "danger", true);
    return Promise.reject(e);
  }
}

async function deleteCustomConfig(id) {
  try {
    const resp = await axios.delete(`${PLUGIN_SECRETS_URI}/${id}`);
    addToast("Data deleted successfully", null, "success", true);
    return resp;
  } catch (e) {
    addToast("Failed!", e.parsedMsg.toString(), "danger", true);
    return Promise.reject(e);
  }
}

export {
  PLUGIN_SECRETS_URI,
  createCustomConfig,
  updateCustomConfig,
  deleteCustomConfig,
};
