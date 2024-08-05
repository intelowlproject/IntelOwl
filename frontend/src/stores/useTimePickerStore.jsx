import { create } from "zustand";

// default: 24h
const defaultFromDate = new Date();
defaultFromDate.setDate(defaultFromDate.getDate() - 1);

export const useTimePickerStore = create((set, _get) => ({
  toDateValue: new Date(),
  fromDateValue: defaultFromDate,
  updateFromDate: (date) => {
    set({ fromDateValue: date });
  },
  updateToDate: (date) => {
    set({ toDateValue: date });
  },
}));
