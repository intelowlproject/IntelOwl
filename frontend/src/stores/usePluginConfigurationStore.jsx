import { create } from "zustand";
import axios from "axios";

import { addToast } from "@certego/certego-ui";

import {
  API_BASE_URI,
  ANALYZERS_CONFIG_URI,
  CONNECTORS_CONFIG_URI,
  VISUALIZERS_CONFIG_URI,
  PLAYBOOKS_CONFIG_URI,
} from "../constants/api";

async function downloadAllPlugin(pluginUrl) {
  const pageSize = 20;
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
        })
      );
    }
    const multipleResponses = await Promise.all(additionalRequests);
    multipleResponses.forEach((response) => {
      pluginList = pluginList.concat(response.data.results);
    });
  }
  return pluginList;
}

const usePluginConfigurationStore = create((set, get) => ({
  // loading: true,
  analyzersLoading: true,
  connectorsLoading: true,
  visualizersLoading: true,
  playbooksLoading: true,
  analyzersError: null,
  connectorsError: null,
  playbooksError: null,
  visualizersError: null,
  analyzers: [],
  connectors: [],
  visualizers: [],
  playbooks: [],
  hydrate: () => {
    // this function is called to check if we need to download the data related to the plugins or not
    if (get().analyzersLoading) {
      get().retrieveAnalyzersConfiguration();
    }
    if (get().connectorsLoading) {
      get().retrieveConnectorsConfiguration();
    }
    if (get().visualizersLoading) {
      get().retrieveVisualizersConfiguration();
    }
    if (get().playbooksLoading) {
      get().retrievePlaybooksConfiguration();
    }
  },
  retrieveAnalyzersConfiguration: async () => {
    try {
      set({ analyzersLoading: true });
      console.debug(
        "usePluginConfigurationStore - retrieveAnalyzersConfiguration: "
      );
      const analyzers = await downloadAllPlugin(ANALYZERS_CONFIG_URI);
      console.debug(analyzers);
      set({
        analyzersError: null,
        analyzers,
        analyzersLoading: false,
      });
    } catch (e) {
      set({ analyzersError: e, analyzersLoading: false });
    }
  },
  retrieveConnectorsConfiguration: async () => {
    try {
      set({ connectorsLoading: true });
      const connectors = await downloadAllPlugin(CONNECTORS_CONFIG_URI);
      console.debug(
        "usePluginConfigurationStore - retrieveConnectorsConfiguration: "
      );
      console.debug(connectors);
      set({
        connectorsError: null,
        connectors,
        connectorsLoading: false,
      });
    } catch (e) {
      set({ connectorsError: e, connectorsLoading: false });
    }
  },
  retrieveVisualizersConfiguration: async () => {
    try {
      set({ visualizersLoading: true });
      const visualizers = await downloadAllPlugin(VISUALIZERS_CONFIG_URI);
      console.debug(
        "usePluginConfigurationStore - retrieveVisualizersConfiguration: "
      );
      console.debug(visualizers);
      set({
        visualizersError: null,
        visualizers,
        visualizersLoading: false,
      });
    } catch (e) {
      set({ visualizersError: e, visualizersLoading: false });
    }
  },
  retrievePlaybooksConfiguration: async () => {
    try {
      set({ playbooksLoading: true });
      const playbooks = await downloadAllPlugin(PLAYBOOKS_CONFIG_URI);
      // convert data
      playbooks.forEach((playbook) => {
        // convert analyzers
        const mappedAnalyzers = playbook.analyzers.map((analyzerName) =>
          Object.fromEntries([
            ["name", analyzerName],
            [
              "config",
              playbook.runtime_configuration.analyzers[analyzerName] || {},
            ],
          ])
        );
        // eslint-disable-next-line no-param-reassign
        playbook.analyzers = {};
        mappedAnalyzers.forEach((analyzer) => {
          // eslint-disable-next-line no-param-reassign
          playbook.analyzers[analyzer.name] = analyzer.config;
        });
        // convert connectors
        const mappedConnectors = playbook.connectors.map((connectorName) =>
          Object.fromEntries([
            ["name", connectorName],
            [
              "config",
              playbook.runtime_configuration.connectors[connectorName] || {},
            ],
          ])
        );
        // eslint-disable-next-line no-param-reassign
        playbook.connectors = {};
        mappedConnectors.forEach((connector) => {
          // eslint-disable-next-line no-param-reassign
          playbook.connectors[connector.name] = connector.config;
        });
        // eslint-disable-next-line no-param-reassign
        delete playbook.runtime_configuration;
      });
      console.debug(
        "usePluginConfigurationStore - retrievePlaybooksConfiguration: "
      );
      console.debug(playbooks);
      set({
        playbooksError: null,
        playbooks,
        playbooksLoading: false,
      });
    } catch (e) {
      set({ playbooksError: e, playbooksLoading: false });
    }
  },
  checkPluginHealth: async (pluginType, PluginName) => {
    try {
      const resp = await axios.get(
        `${API_BASE_URI}/${pluginType}/${PluginName}/healthcheck`
      );
      console.debug("usePluginConfigurationStore - checkPluginHealth: ");
      console.debug(resp);
      return Promise.resolve(resp.data?.status); // status is of type boolean
    } catch (e) {
      addToast("Failed!", e.parsedMsg.toString(), "danger");
      return null;
    }
  },
}));

export default usePluginConfigurationStore;
