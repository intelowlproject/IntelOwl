import React from "react";
import useAxios from "axios-hooks";
import useTitle from "react-use/lib/useTitle";
import useInterval from "react-use/lib/useInterval";
import { useParams } from "react-router-dom";

import { Loader } from "@certego/certego-ui";
import { ANALYSIS_BASE_URI } from "../../../constants/apiURLs";
import { AnalysisOverview } from "./AnalysisOverview";

export default function AnalysisResult() {
  console.debug("AnalysisResult rendered!");

  // local state
  const [initialLoading, setInitialLoading] = React.useState(true);
  const [isRunning, setIsRunning] = React.useState(false);

  // from props
  const params = useParams();
  const analysisId = params.id;

  // API to download the job data
  const [{ data: analysis, loading, error }, refetch] = useAxios({
    url: `${ANALYSIS_BASE_URI}/${analysisId}`,
  });

  // in case the job is not running and started (the job is not undefined) it means it terminated.
  const analysisConcluded = analysis !== undefined && !isRunning;

  console.debug(
    `AnalysisResult - initialLoading: ${initialLoading}, isRunning: ${isRunning}, ` +
      ` analysisConcluded: ${analysisConcluded}`,
  );

  // HTTP polling only in case the analysis is running
  useInterval(
    refetch,
    isRunning ? 5 * 1000 : null, // 5 seconds
  );

  // every time the analysis data are downloaded we check if it terminated or not
  React.useEffect(
    () =>
      setIsRunning(
        analysis === undefined || ["running"].includes(analysis.status),
      ),
    [analysis],
  );

  // initial loading (spinner)
  React.useEffect(() => {
    if (!loading) setInitialLoading(false);
  }, [loading]);

  // page title
  useTitle(`IntelOwl | Analysis (#${analysisId})`, { restoreOnUnmount: true });

  return (
    <Loader
      loading={initialLoading}
      error={error}
      render={() => (
        <AnalysisOverview isRunningAnalysis={isRunning} analysis={analysis} />
      )}
    />
  );
}
