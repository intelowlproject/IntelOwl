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

async function downloadAllPlugin(pluginUrl, currentPage = 1) {
  const resp = await axios.get(pluginUrl, { params: { page: currentPage } });
  let additionalData = [];
  if (currentPage < resp.data.total_pages) {
    additionalData = await downloadAllPlugin(pluginUrl, currentPage + 1);
  }
  return resp.data.results.concat(additionalData);
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
  analyzersJSON: {},
  analyzers: [],
  connectorsJSON: {},
  connectors: [],
  visualizersJSON: {},
  visualizers: [],
  playbooksJSON: {},
  playbooks: [],
  hydrate: () => {
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
        analyzersJSON: analyzers,
        analyzers: Object.values(analyzers),
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
        connectorsJSON: connectors,
        connectors: Object.values(connectors),
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
        visualizersJSON: visualizers,
        visualizers: Object.values(visualizers),
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
      console.debug(
        "usePluginConfigurationStore - retrievePlaybooksConfiguration: "
      );
      console.debug(playbooks);
      set({
        playbooksError: null,
        playbooksJSON: playbooks,
        playbooks: Object.values(playbooks),
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
