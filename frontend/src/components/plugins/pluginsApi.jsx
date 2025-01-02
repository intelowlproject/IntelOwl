import axios from "axios";

import { addToast } from "@certego/certego-ui";
import { API_BASE_URI } from "../../constants/apiURLs";
import { prettifyErrors } from "../../utils/api";

export async function createConfiguration(type, data) {
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
    return { success, data: response.data };
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
}

export async function createPluginConfig(type, pluginName, data) {
  let success = false;
  try {
    const response = await axios.post(
      `${API_BASE_URI}/${type}/${pluginName}/plugin_config`,
      data,
    );
    success = response.status === 201;
    if (success) {
      addToast(`plugin config created with success`, null, "success");
    }
  } catch (error) {
    addToast(
      `Failed creation of plugin config`,
      prettifyErrors(error),
      "warning",
      true,
      10000,
    );
    return { success, error: prettifyErrors(error) };
  }
  return { success };
}

export async function editConfiguration(type, pluginName, data) {
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
    return { success, data: response.data };
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
}

export async function editPluginConfig(type, pluginName, data) {
  let success = false;
  try {
    const response = await axios.patch(
      `${API_BASE_URI}/${type}/${pluginName}/plugin_config`,
      data,
    );
    success = response.status === 200;
    if (success) {
      addToast(`plugin config saved`, null, "success");
    }
  } catch (error) {
    addToast(
      `Failed to edited plugin config`,
      prettifyErrors(error),
      "warning",
      true,
      10000,
    );
    return { success, error: prettifyErrors(error) };
  }
  return { success };
}

export async function deleteConfiguration(type, pluginName) {
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

export async function deletePluginConfig(pluginId) {
  try {
    const response = await axios.delete(
      `${API_BASE_URI}/plugin-config/${pluginId}`,
    );
    addToast(
      `Plugin config with id ${pluginId} deleted with success`,
      null,
      "success",
    );
    return Promise.resolve(response);
  } catch (error) {
    addToast(
      `Failed deletion of plugin config with id ${pluginId}`,
      prettifyErrors(error),
      "warning",
      true,
    );
    return null;
  }
}
