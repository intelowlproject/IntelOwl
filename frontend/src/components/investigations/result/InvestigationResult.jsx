import React from "react";
import useAxios from "axios-hooks";
import useTitle from "react-use/lib/useTitle";
import useInterval from "react-use/lib/useInterval";
import { useParams } from "react-router-dom";

import { Loader } from "@certego/certego-ui";
import { INVESTIGATION_BASE_URI } from "../../../constants/apiURLs";
import { InvestigationOverview } from "./InvestigationOverview";

export default function InvestigationResult() {
  console.debug("InvestigationResult rendered!");

  // local state
  const [initialLoading, setInitialLoading] = React.useState(true);
  const [isRunning, setIsRunning] = React.useState(false);

  // from props
  const params = useParams();
  const investigationId = params.id;

  // API to download the investigation data
  const [{ data: investigation, loading, error }, refetchInvestigation] =
    useAxios({
      url: `${INVESTIGATION_BASE_URI}/${investigationId}`,
    });

  // in case the investigation is not running and started (the investigation is not undefined) it means it terminated.
  const investigationConcluded = investigation !== undefined && !isRunning;

  console.debug(
    `InvestigationResult - initialLoading: ${initialLoading}, isRunning: ${isRunning}, ` +
      ` investigationConcluded: ${investigationConcluded}, error: ${error}`,
  );

  // HTTP polling only in case the investigation is running
  useInterval(
    refetchInvestigation,
    isRunning ? 5 * 1000 : null, // 5 seconds
  );

  // every time the investigation data are downloaded we check if it terminated or not
  React.useEffect(() => {
    setIsRunning(
      // in case investigation is unedifined and with an error -> not found, set to false
      (investigation === undefined && !error) ||
        ["running"].includes(investigation?.status),
    );
  }, [investigation, error]);

  // initial loading (spinner)
  React.useEffect(() => {
    if (!loading) setInitialLoading(false);
  }, [loading]);

  // page title
  useTitle(`IntelOwl | Investigation (#${investigationId})`, {
    restoreOnUnmount: true,
  });

  return (
    <Loader
      loading={initialLoading}
      error={error}
      render={() => (
        <InvestigationOverview
          isRunningInvestigation={isRunning}
          investigation={investigation}
          refetchInvestigation={refetchInvestigation}
        />
      )}
    />
  );
}
