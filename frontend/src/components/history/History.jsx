import React, { Suspense } from "react";
import { useLocation, useSearchParams } from "react-router-dom";

import { FallBackLoading } from "@certego/certego-ui";
import { useGuideContext } from "../../contexts/GuideContext";
import { HistoryPages } from "../../constants/miscConst";
import { HistoryTable } from "./HistoryTable";
import { HistoryNav } from "./HistoryNav";

export default function History() {
  console.debug("History rendered");
  const location = useLocation();
  const [searchParams, _] = useSearchParams();

  const { guideState, setGuideState } = useGuideContext();

  React.useEffect(() => {
    if (guideState.tourActive) {
      setTimeout(() => {
        setGuideState({ run: true, stepIndex: 7 });
      }, 200);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const pageType = location?.pathname?.split("/")[2];
  let startTimeString = "event_date__gte";
  let endTimeString = "event_date__lte";

  if (pageType === HistoryPages.JOB) {
    startTimeString = "received_request_time__gte";
    endTimeString = "received_request_time__lte";
  } else if (pageType === HistoryPages.INVESTIGAITON) {
    startTimeString = "start_time__gte";
    endTimeString = "start_time__lte";
  }

  const startTimeParam = searchParams.get(startTimeString);
  const endTimeParam = searchParams.get(endTimeString);

  return (
    <>
      <HistoryNav
        pageType={pageType}
        startTimeParam={startTimeParam}
        endTimeParam={endTimeParam}
      />
      {/* This is way to generate only the table the user wants this allow to save:
       * requests to the backend
       * loading time
       * avoid error when request job page 3 and jobs has for ex 6 pages and investigations 2 */}
      <Suspense fallback={<FallBackLoading />}>
        <HistoryTable
          startTimeParam={startTimeParam}
          endTimeParam={endTimeParam}
          pageType={pageType}
        />
      </Suspense>
    </>
  );
}
