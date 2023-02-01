import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";

// constants
const LOCALSTORAGE_KEY = "intelowl-recent-scans-store";
const useRecentScansStore = create(
  persist(
    (set) => ({
      jobIdStatusMap: {}, // {1: "success"}
      append: (id, status) => {
        set((state) => ({
          jobIdStatusMap: {
            // all this shitty logic is just to limit the object length to latest 10
            ...Object.fromEntries(
              Object.entries(state.jobIdStatusMap)
                .sort(([k1], [k2]) => k1 - k2)
                .slice(
                  Math.max(Object.keys(state.jobIdStatusMap).length - 9, 0)
                )
            ),
            [id]: status,
          },
        }));
      },
      clear: () => {
        localStorage.removeItem(LOCALSTORAGE_KEY);
      },
    }),
    {
      name: LOCALSTORAGE_KEY,
      storage: createJSONStorage(() => localStorage),
    }
  )
);

export default useRecentScansStore;
