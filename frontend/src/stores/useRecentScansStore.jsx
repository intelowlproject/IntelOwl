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
  fetchRecentScansUser: async (isSample) => {
    try {
      set({ loadingScansUser: true });
      const resp = await axios.post(JOB_RECENT_SCANS_USER, {
        is_sample: isSample,
      });
      set({
        recentScansUser: resp.data,
        loadingScansUser: false,
      });
    } catch (error) {
      set({ recentScansUserError: error, loadingScansUser: false });
    }
  },
  fetchRecentScans: async (md5, isSample) => {
    const body = {};
    body.md5 = md5;
    if (isSample) body.max_temporal_distance = 60;
    try {
      set({ loadingScansInsertedAnalyzable: true });
      const resp = await axios.post(JOB_RECENT_SCANS, body);
      set({
        recentScans: resp.data,
        loadingScansInsertedAnalyzable: false,
      });
    } catch (error) {
      set({ recentScansError: error, loadingScansInsertedAnalyzable: false });
    }
  },
}));
