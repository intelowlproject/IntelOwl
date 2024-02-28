import axios from "axios";

import { addToast } from "@certego/certego-ui";

import { PLUGIN_CONFIG_URI } from "../../../constants/apiURLs";

async function createCustomConfig(data) {
  console.debug("createCustomConfig - data:");
  console.debug(data);
  try {
    const resp = await axios.post(PLUGIN_CONFIG_URI, data);
    addToast("Data posted successfully", null, "success", true);
    return resp;
  } catch (error) {
    if (
      error?.response.status === 400 &&
      error.response?.data?.errors?.non_field_errors[0].endsWith(
        "already exists.",
      )
    )
      addToast("Failed!", "This config already exists!", "danger", true);
    else addToast("Failed!", error.parsedMsg.toString(), "danger", true);
    return Promise.reject(error);
  }
}

async function updateCustomConfig(value, id) {
  console.debug("updateCustomConfig - value:");
  console.debug(value);
  try {
    const resp = await axios.patch(`${PLUGIN_CONFIG_URI}/${id}`, { value });
    addToast("Data updated successfully", null, "success", true);
    return resp;
  } catch (error) {
    addToast("Failed!", error.parsedMsg.toString(), "danger", true);
    return Promise.reject(error);
  }
}

async function deleteCustomConfig(id) {
  console.debug("deleteCustomConfig - id:");
  console.debug(id);
  try {
    const resp = await axios.delete(`${PLUGIN_CONFIG_URI}/${id}`);
    addToast("Data deleted successfully", null, "success", true);
    return resp;
  } catch (error) {
    addToast("Failed!", error.parsedMsg.toString(), "danger", true);
    return Promise.reject(error);
  }
}

export {
  PLUGIN_CONFIG_URI,
  createCustomConfig,
  updateCustomConfig,
  deleteCustomConfig,
};
