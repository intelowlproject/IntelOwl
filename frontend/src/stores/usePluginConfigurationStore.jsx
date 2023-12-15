import { create } from "zustand";
import axios from "axios";

import { addToast } from "@certego/certego-ui";

import { PluginsTypes } from "../constants/pluginConst";
import {
  API_BASE_URI,
  ANALYZERS_CONFIG_URI,
  CONNECTORS_CONFIG_URI,
  PIVOTS_CONFIG_URI,
  VISUALIZERS_CONFIG_URI,
  PLAYBOOKS_CONFIG_URI,
  INGESTORS_CONFIG_URI,
} from "../constants/apiURLs";
import { prettifyErrors } from "../utils/api";

async function downloadAllPlugin(pluginUrl) {
  const pageSize = 70;
  let pluginList = [];
  // we need to request the first chunk to know how many chunks are available
  const resp = await axios.get(pluginUrl, {
    params: { page: 1, page_size: pageSize },
  });
  pluginList = pluginList.concat(resp.data.results);

  // in case there are others chunks, download all of them concurrently
  if (resp.data.total_pages > 1) {
    const additionalRequests = [];
    for (
      let addtionalPageIndex = 2;
      addtionalPageIndex <= resp.data.total_pages;
      addtionalPageIndex += 1
    ) {
      additionalRequests.push(
        axios.get(pluginUrl, {
          params: { page: addtionalPageIndex, page_size: pageSize },
        }),
      );
    }
    const multipleResponses = await Promise.all(additionalRequests);
    multipleResponses.forEach((response) => {
      pluginList = pluginList.concat(response.data.results);
    });
  }
  return pluginList;
}

export const usePluginConfigurationStore = create((set, get) => ({
  // loading: true,
  analyzersLoading: true,
  connectorsLoading: true,
  pivotsLoading: true,
  visualizersLoading: true,
  ingestorsLoading: true,
  playbooksLoading: true,
  analyzersError: null,
  connectorsError: null,
  pivotsError: null,
  visualizersError: null,
  ingestorsError: null,
  playbooksError: null,
  analyzers: [],
  connectors: [],
  pivots: [],
  visualizers: [],
  ingestors: [],
  playbooks: [],
  hydrate: () => {
    // this function is called to check if we need to download the data related to the plugins or not
    if (get().analyzersLoading) {
      get().retrieveAnalyzersConfiguration();
    }
    if (get().connectorsLoading) {
      get().retrieveConnectorsConfiguration();
    }
    if (get().pivotsLoading) {
      get().retrievePivotsConfiguration();
    }
    if (get().visualizersLoading) {
      get().retrieveVisualizersConfiguration();
    }
    if (get().ingestorsLoading) {
      get().retrieveIngestorsConfiguration();
    }
    if (get().playbooksLoading) {
      get().retrievePlaybooksConfiguration();
    }
  },
  retrieveAnalyzersConfiguration: async () => {
    try {
      set({ analyzersLoading: true });
      console.debug(
        "usePluginConfigurationStore - retrieveAnalyzersConfiguration: ",
      );
      const analyzers = await downloadAllPlugin(ANALYZERS_CONFIG_URI);
      console.debug(analyzers);
      set({
        analyzersError: null,
        analyzers,
        analyzersLoading: false,
      });
    } catch (error) {
      set({ analyzersError: error, analyzersLoading: false });
    }
  },
  retrieveConnectorsConfiguration: async () => {
    try {
      set({ connectorsLoading: true });
      const connectors = await downloadAllPlugin(CONNECTORS_CONFIG_URI);
      console.debug(
        "usePluginConfigurationStore - retrieveConnectorsConfiguration: ",
      );
      console.debug(connectors);
      set({
        connectorsError: null,
        connectors,
        connectorsLoading: false,
      });
    } catch (error) {
      set({ connectorsError: error, connectorsLoading: false });
    }
  },
  retrieveVisualizersConfiguration: async () => {
    try {
      set({ visualizersLoading: true });
      const visualizers = await downloadAllPlugin(VISUALIZERS_CONFIG_URI);
      console.debug(
        "usePluginConfigurationStore - retrieveVisualizersConfiguration: ",
      );
      console.debug(visualizers);
      set({
        visualizersError: null,
        visualizers,
        visualizersLoading: false,
      });
    } catch (error) {
      set({ visualizersError: error, visualizersLoading: false });
    }
  },
  retrieveIngestorsConfiguration: async () => {
    try {
      set({ ingestorsLoading: true });
      const ingestors = await downloadAllPlugin(INGESTORS_CONFIG_URI);
      console.debug(
        "usePluginConfigurationStore - retrieveIngestorsConfiguration: ",
      );
      console.debug(ingestors);
      set({
        ingestorsError: null,
        ingestors,
        ingestorsLoading: false,
      });
    } catch (error) {
      set({ ingestorsError: error, ingestorsLoading: false });
    }
  },
  retrievePivotsConfiguration: async () => {
    try {
      set({ pivotsLoading: true });
      const pivots = await downloadAllPlugin(PIVOTS_CONFIG_URI);
      console.debug(
        "usePluginConfigurationStore - retrievePivotsConfiguration: ",
      );
      console.debug(pivots);
      set({
        pivotsError: null,
        pivots,
        pivotsLoading: false,
      });
    } catch (error) {
      set({ pivotsError: error, pivotsLoading: false });
    }
  },
  retrievePlaybooksConfiguration: async () => {
    try {
      set({ playbooksLoading: true });
      const playbooks = await downloadAllPlugin(PLAYBOOKS_CONFIG_URI);
      console.debug(
        "usePluginConfigurationStore - retrievePlaybooksConfiguration: ",
      );
      console.debug(playbooks);
      set({
        playbooksError: null,
        playbooks,
        playbooksLoading: false,
      });
    } catch (error) {
      set({ playbooksError: error, playbooksLoading: false });
    }
  },
  checkPluginHealth: async (type, PluginName) => {
    try {
      const resp = await axios.get(
        `${API_BASE_URI}/${type}/${PluginName}/health_check`,
      );
      console.debug("usePluginConfigurationStore - checkPluginHealth: ");
      console.debug(resp);
      if (resp.data?.status)
        addToast(
          `${PluginName} - health check: success`,
          "It is up and running",
          "success",
          true,
        );
      else
        addToast(
          `${PluginName} - health check: warning`,
          "It is NOT up",
          "warning",
          true,
        );
      return Promise.resolve(resp.status);
    } catch (error) {
      console.error(error);
      addToast(
        `${PluginName} - health check: failed`,
        prettifyErrors(error),
        "danger",
        true,
      );
      return error.response.status;
    }
  },
  pluginPull: async (type, PluginName) => {
    try {
      const resp = await axios.post(
        `${API_BASE_URI}/${type}/${PluginName}/pull`,
      );
      console.debug("usePluginConfigurationStore - pluginPull: ");
      console.debug(resp);
      if (resp.data?.status)
        addToast(
          "Plugin pull: success",
          `${PluginName} updated`,
          "success",
          true,
        );
      else
        addToast(
          "Plugin pull: warning",
          `${PluginName} pull failed`,
          "warning",
          true,
        );
      return Promise.resolve(resp.status);
    } catch (error) {
      addToast("Plugin pull: failed", prettifyErrors(error), "danger", true);
      return error.response.status;
    }
  },
  deletePlaybook: async (playbook) => {
    try {
      const response = await axios.delete(
        `${PLAYBOOKS_CONFIG_URI}/${playbook}`,
      );
      addToast(`${playbook} deleted`, null, "info");
      return Promise.resolve(response);
    } catch (error) {
      addToast("Failed!", prettifyErrors(error), "danger");
      return null;
    }
  },
  enablePluginInOrg: async (type, pluginName, pluginOwner) => {
    if (type === PluginsTypes.PLAYBOOK && pluginOwner !== null) {
      try {
        const response = await axios.patch(
          `${API_BASE_URI}/${type}/${pluginName}`,
          { for_organization: true },
        );
        addToast(`${pluginName} enabled for the organization`, null, "success");
        get().retrievePlaybooksConfiguration();
        return Promise.resolve(response);
      } catch (error) {
        addToast(
          `Failed to enabled ${pluginName} for the organization`,
          prettifyErrors(error),
          "danger",
          true,
        );
        return null;
      }
    }
    try {
      const response = await axios.delete(
        `${API_BASE_URI}/${type}/${pluginName}/organization`,
      );
      addToast(`${pluginName} enabled for the organization`, null, "success");
      return Promise.resolve(response);
    } catch (error) {
      addToast(
        `Failed to enabled ${pluginName} for the organization`,
        prettifyErrors(error),
        "danger",
        true,
      );
      return null;
    }
  },
  disabledPluginInOrg: async (type, pluginName, pluginOwner) => {
    if (type === PluginsTypes.PLAYBOOK && pluginOwner !== null) {
      try {
        const response = await axios.patch(
          `${API_BASE_URI}/${type}/${pluginName}`,
          { for_organization: false },
        );
        addToast(`${pluginName} disabled for the organization`, null, "info");
        get().retrievePlaybooksConfiguration();
        return Promise.resolve(response);
      } catch (error) {
        addToast(
          `Failed to disabled ${pluginName} for the organization`,
          prettifyErrors(error),
          "danger",
          true,
        );
        return null;
      }
    }
    try {
      const response = await axios.post(
        `${API_BASE_URI}/${type}/${pluginName}/organization`,
      );
      addToast(`${pluginName} disabled for the organization`, null, "info");
      return Promise.resolve(response);
    } catch (error) {
      addToast(
        `Failed to disabled ${pluginName} for the organization`,
        prettifyErrors(error),
        "danger",
        true,
      );
      return null;
    }
  },
}));
