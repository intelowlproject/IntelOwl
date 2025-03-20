import { create } from "zustand";

export const useJsonEditorStore = create((set, _get) => ({
  textToHighlight: "",
  setTextToHighlight: (data) => {
    set({ textToHighlight: data });
  },
}));
