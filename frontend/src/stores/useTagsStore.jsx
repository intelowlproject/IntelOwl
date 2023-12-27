import { create } from "zustand";
import axios from "axios";

import { TAG_BASE_URI } from "../constants/apiURLs";

export const useTagsStore = create((set, _get) => ({
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
    } catch (error) {
      set({ error, loading: false });
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
    } catch (error) {
      return Promise.reject(error);
    }
  },
  update: async (tagId, body) => {
    try {
      const resp = await axios.patch(`${TAG_BASE_URI}/${tagId}`, body);
      set((state) => ({
        ...state,
        tags: [...state.tags.filter((tag) => tag.id !== tagId), resp.data],
      }));
      return Promise.resolve(resp.data);
    } catch (error) {
      return Promise.reject(error);
    }
  },
}));
