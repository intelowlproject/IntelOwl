import axios from "axios";

import { addToast } from "@certego/certego-ui";
import { API_BASE_URI } from "../../constants/apiURLs";
import { prettifyErrors } from "../../utils/api";

export async function createPluginConfig(type, data) {
  let success = false;
  try {
    const response = await axios.post(`${API_BASE_URI}/${type}`, data);
    success = response.status === 201;
    if (success) {
      addToast(
        `${type} with name ${response.data.name} created with success`,
        null,
        "success",
      );
    }
  } catch (error) {
    addToast(
      `Failed creation of ${type} with name ${data.name}`,
      prettifyErrors(error),
      "warning",
      true,
      10000,
    );
    return { success, error: prettifyErrors(error) };
  }
  return { success };
}

export async function editPluginConfig(type, pluginName, data) {
  let success = false;
  try {
    const response = await axios.patch(
      `${API_BASE_URI}/${type}/${pluginName}`,
      data,
    );
    success = response.status === 200;
    if (success) {
      addToast(`${data.name} configuration saved`, null, "success");
    }
  } catch (error) {
    addToast(
      `Failed to edited ${type} with name ${data.name}`,
      prettifyErrors(error),
      "warning",
      true,
      10000,
    );
    return { success, error: prettifyErrors(error) };
  }
  return { success };
}

export async function deletePluginConfig(type, pluginName) {
  try {
    const response = await axios.delete(
      `${API_BASE_URI}/${type}/${pluginName}`,
    );
    addToast(
      `${type} with name ${pluginName} deleted with success`,
      null,
      "success",
    );
    return Promise.resolve(response);
  } catch (error) {
    addToast(
      `Failed deletion of ${type} with name ${pluginName}`,
      prettifyErrors(error),
      "warning",
      true,
    );
    return null;
  }
}
