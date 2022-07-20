import axios from "axios";

import { addToast } from "@certego/certego-ui";

import { CUSTOM_CONFIG_URI } from "../../../constants/api";

// API Access

async function createCustomConfig(data) {
  try {
    const resp = await axios.post(CUSTOM_CONFIG_URI, data);
    addToast("Data posted successfully", null, "success", true);
    return resp;
  } catch (e) {
    addToast("Failed!", e.parsedMsg.toString(), "danger", true);
    return Promise.reject(e);
  }
}

async function updateCustomConfig(data, id) {
  try {
    const resp = await axios.patch(`${CUSTOM_CONFIG_URI}/${id}`, data);
    addToast("Data updated successfully", null, "success", true);
    return resp;
  } catch (e) {
    addToast("Failed!", e.parsedMsg.toString(), "danger", true);
    return Promise.reject(e);
  }
}

async function deleteCustomConfig(id) {
  try {
    const resp = await axios.delete(`${CUSTOM_CONFIG_URI}/${id}`);
    addToast("Data deleted successfully", null, "success", true);
    return resp;
  } catch (e) {
    addToast("Failed!", e.parsedMsg.toString(), "danger", true);
    return Promise.reject(e);
  }
}

export {
  CUSTOM_CONFIG_URI,
  createCustomConfig,
  updateCustomConfig,
  deleteCustomConfig,
};
