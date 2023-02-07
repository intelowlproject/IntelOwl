import { create } from "zustand";
import axios from "axios";

import { TAG_BASE_URI } from "../constants/api";

const useTagsStore = create((set, _get) => ({
  loading: true,
  error: null,
  tags: [],
  list: async () => {
    try {
      set({ loading: true });
      const resp = await axios.get(TAG_BASE_URI);
      set({
        tags: resp.data,
        loading: false,
      });
    } catch (e) {
      set({ error: e, loading: false });
    }
  },
  create: async (label, color) => {
    try {
      const resp = await axios.post(TAG_BASE_URI, { label, color });
      set((state) => ({
        ...state,
        tags: [...state.tags, resp.data],
      }));
      return Promise.resolve(resp.data);
    } catch (e) {
      return Promise.reject(e);
    }
  },
  update: async (tagId, body) => {
    try {
      const resp = await axios.patch(`${TAG_BASE_URI}/${tagId}`, body);
      set((state) => ({
        ...state,
        tags: [...state.tags.filter((t) => t.id !== tagId), resp.data],
      }));
      return Promise.resolve(resp.data);
    } catch (e) {
      return Promise.reject(e);
    }
  },
}));

export default useTagsStore;
