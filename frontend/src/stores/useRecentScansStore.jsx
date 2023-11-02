import { create } from "zustand";
import axios from "axios";

import { JOB_RECENT_SCANS, JOB_RECENT_SCANS_USER } from "../constants/apiURLs";

export const useRecentScansStore = create((set, _get) => ({
  loadingScansUser: true,
  loadingScansInsertedAnalyzable: true,
  recentScansUserError: null,
  recentScansError: null,
  recentScansUser: [],
  recentScans: [],
  fetchRecentScansUser: async () => {
    try {
      set({ loadingScansUser: true });
      const resp = await axios.post(JOB_RECENT_SCANS_USER);
      set({
        recentScansUser: resp.data,
        loadingScansUser: false,
      });
    } catch (e) {
      set({ recentScansUserError: e, loadingScansUser: false });
    }
  },
  fetchRecentscans: async (md5) => {
    try {
      set({ loadingScansInsertedAnalyzable: true });
      const resp = await axios.post(JOB_RECENT_SCANS, { md5 });
      set({
        recentScans: resp.data,
        loadingScansInsertedAnalyzable: false,
      });
    } catch (e) {
      set({ recentScansError: e, loadingScansInsertedAnalyzable: false });
    }
  },
}));
