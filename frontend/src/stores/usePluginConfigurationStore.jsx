import create from "zustand";
import axios from "axios";

import { addToast } from "@certego/certego-ui";

import {
  API_BASE_URI,
  ANALYZERS_CONFIG_URI,
  CONNECTORS_CONFIG_URI,
  PLAYBOOKS_CONFIG_URI,
} from "../constants/api";

const usePluginConfigurationStore = create((set, get) => ({
  loading: true,
  error: null,
  analyzersJSON: {},
  analyzers: [],
  connectorsJSON: {},
  connectors: [],
  playbooksJSON: {},
  playbooks: [],
  hydrate: () => {
    if (!get().loading) return;
    get().retrieveAnalyzersConfiguration();
    get().retrieveConnectorsConfiguration();
    get().retrievePlaybooksConfiguration();
  },
  retrieveAnalyzersConfiguration: async () => {
    try {
      set({ loading: true });
      const resp = await axios.get(ANALYZERS_CONFIG_URI);
      set({
        analyzersJSON: resp.data,
        analyzers: Object.values(resp.data),
        loading: false,
      });
    } catch (e) {
      set({ error: e, loading: false });
    }
  },
  retrieveConnectorsConfiguration: async () => {
    try {
      set({ loading: true });
      const resp = await axios.get(CONNECTORS_CONFIG_URI);
      set({
        connectorsJSON: resp.data,
        connectors: Object.values(resp.data),
        loading: false,
      });
    } catch (e) {
      set({ error: e, loading: false });
    }
  },
  retrievePlaybooksConfiguration: async () => {
    try {
      set({ loading: true });
      const resp = await axios.get(PLAYBOOKS_CONFIG_URI);
      set({
        playbooksJSON: resp.data,
        playbooks: Object.values(resp.data),
        loading: false,
      });
    } catch (e) {
      set({ error: e, loading: false });
    }
  },
  checkPluginHealth: async (pluginType, PluginName) => {
    try {
      const resp = await axios.get(
        `${API_BASE_URI}/${pluginType}/${PluginName}/healthcheck`
      );
      return Promise.resolve(resp.data?.status); // status is of type boolean
    } catch (e) {
      addToast("Failed!", e.parsedMsg.toString(), "danger");
      return null;
    }
  },
}));

export default usePluginConfigurationStore;
