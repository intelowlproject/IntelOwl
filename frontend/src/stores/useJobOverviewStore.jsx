/* This store is used to save the data about the section selected by the user in the JobOverview (raw or UI).

This store is required because we have a problem with the rendering logic for the jobs:
JobResult correctly handle the polling and the rendering of the job data (when some data are available).
JobOverview need to wrap the job's metadata, the UI and the raw format.
Unfortunately in case the jobs require some time to be completed the JobResult perform other requests and this lead to a re-render of JobOverview.
If the section(UI/raw) selection is stored in JobOverview's state, for each request the preference is resetted:
we need to move the user selection preference outside the component (here).
*/

import { create } from "zustand";

const useJobOverviewStore = create((set) => ({
  isSelectedUI: true,
  activeElement: undefined,
  setIsSelectedUI: (isSelectedUI) => set(() => ({ isSelectedUI })),
  setActiveElement: (activeElement) => set(() => ({ activeElement })),
  resetJobOverview: () =>
    set(() => ({ isSelectedUI: true, activeElement: undefined })),
}));

export default useJobOverviewStore;
