import { create } from "zustand";
import axios from "axios";

import { addToast } from "@certego/certego-ui";

import {
  API_BASE_URI,
  ANALYZERS_CONFIG_URI,
  CONNECTORS_CONFIG_URI,
  PIVOTS_CONFIG_URI,
  VISUALIZERS_CONFIG_URI,
  PLAYBOOKS_CONFIG_URI,
  INGESTORS_CONFIG_URI,
} from "../constants/apiURLs";

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

const usePluginConfigurationStore = create((set, get) => ({
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
    } catch (e) {
      set({ analyzersError: e, analyzersLoading: false });
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
    } catch (e) {
      set({ connectorsError: e, connectorsLoading: false });
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
    } catch (e) {
      set({ visualizersError: e, visualizersLoading: false });
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
    } catch (e) {
      set({ ingestorsError: e, ingestorsLoading: false });
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
    } catch (e) {
      set({ pivotsError: e, pivotsLoading: false });
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
          ]),
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
          ]),
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
        "usePluginConfigurationStore - retrievePlaybooksConfiguration: ",
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
  checkPluginHealth: async (PluginTypesNumeric, PluginName) => {
    try {
      const resp = await axios.get(
        `${API_BASE_URI}/${PluginTypesNumeric}/${PluginName}/health_check`,
      );
      console.debug("usePluginConfigurationStore - checkPluginHealth: ");
      console.debug(resp);
      return Promise.resolve(resp.data?.status); // status is of type boolean
    } catch (e) {
      addToast("Failed!", e.parsedMsg.toString(), "danger");
      return null;
    }
  },
  deletePlaybook: async (playbook) => {
    try {
      const response = await axios.delete(
        `${PLAYBOOKS_CONFIG_URI}/${playbook}`,
      );
      addToast(`${playbook} deleted`, null, "info");
      return Promise.resolve(response);
    } catch (e) {
      addToast("Failed!", e.parsedMsg, "danger");
      return null;
    }
  },
}));

export default usePluginConfigurationStore;
