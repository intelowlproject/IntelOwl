import React, { useEffect } from "react";
import useTitle from "react-use/lib/useTitle";
import { useParams, useLocation } from "react-router-dom";

import { Loader } from "@certego/certego-ui";
import axios from "axios";
import useAxios from "axios-hooks";
import {
  WEBSOCKET_JOBS_URI,
  JOB_BASE_URI,
  ANALYZABLES_URI,
} from "../../../constants/apiURLs";
import { JobOverview } from "./JobOverview";

import {
  generateJobNotification,
  setNotificationFavicon,
} from "../notifications";

import { JobFinalStatuses, JobStatuses } from "../../../constants/jobConst";

export default function JobResult() {
  console.debug("JobResult rendered!");

  // state
  const location = useLocation();
  const [dataIsDownloading, setDataIsDownloading] = React.useState(true);
  const [data, setData] = React.useState({
    relatedInvestigationNumber: undefined,
    job: location.state?.jobReport || undefined,
  });
  // this state var is used to check if we notified the user, in this way we avoid to notify more than once
  const [notified, setNotified] = React.useState(false);
  // this state var is used to check if the user changed page, in case he waited the result on the page we avoid the notification
  const [toNotify, setToNotify] = React.useState(false);

  // from props
  const params = useParams();
  const jobId = params.id;
  const { section } = params;
  const { subSection } = params;

  const jobWebsocket = React.useRef();

  const jobIsRunning =
    data.job === undefined ||
    [
      JobStatuses.PENDING,
      JobStatuses.PENDING,
      JobStatuses.ANALYZERS_RUNNING,
      JobStatuses.ANALYZERS_COMPLETED,
      JobStatuses.CONNECTORS_RUNNING,
      JobStatuses.CONNECTORS_COMPLETED,
      JobStatuses.PIVOTS_RUNNING,
      JobStatuses.PIVOTS_COMPLETED,
      JobStatuses.VISUALIZERS_RUNNING,
      JobStatuses.VISUALIZERS_COMPLETED,
    ].includes(data.job?.status);

  console.debug(
    `JobResult - dataIsDownloading: ${dataIsDownloading}, jobIsRunning: ${jobIsRunning}, ` +
      `notified: ${notified}, toNotify: ${toNotify}`,
  );

  // useAxios caches the request by default
  const [{ data: jobData, loading: jobLoading, error: jobError }, refetchJob] =
    useAxios({
      url: `${JOB_BASE_URI}/${jobId}`,
    });

  useEffect(() => {
    /* INITIAL SETUP:
    - add a focus listener:
     * when gain focus set it has been notified and reset the favicon
     * when lost focus (blur) we set we can notify the user
    - first request with HTTP(S): we avoid to create a ws if not need (ex: old completed jobs)
    */
    window.addEventListener("focus", () => {
      setNotificationFavicon(false);
      setToNotify(false);
    });
    window.addEventListener("blur", () => setToNotify(true));

    console.debug(
      "JobResult - jobLoading useEffect",
      !data.job,
      jobData,
      !jobLoading,
      jobError == null,
    );
    if (!data.job && jobData && !jobLoading && jobError == null) {
      axios
        .get(
          `${ANALYZABLES_URI}/${jobData.analyzable_id}/related_investigation_number`,
        )
        .then((response) => response.data.related_investigation_number)
        .catch((_) => -1)
        // use "then" instead of "finally"vecause it doesn't support parameters
        .then((relatedInvestigationNumber) =>
          setData({ relatedInvestigationNumber, job: jobData }),
        );
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jobLoading]);

  useEffect(() => {
    if (data.job) setDataIsDownloading(false);
  }, [data]);

  // page title
  useTitle(
    `IntelOwl | Job (#${jobId}, ${
      // eslint-disable-next-line no-nested-ternary
      data.job
        ? data.job.is_sample
          ? data.job.file_name
          : data.job.observable_name
        : ""
    })`,
    { restoreOnUnmount: true },
  );

  /* SETUP WS:
  only in case the first request didn't get the job in a final status.
  use ws with useRef to avoid to create a ws each render AND create the ws.
  only in the last page (section and subSection) or we will create 3 ws, one for each redirect:
  jobs/1 -> jobs/1/visualizer -> jobs/1/visualizer/loading
  */
  if (
    data.job &&
    jobIsRunning &&
    section &&
    subSection &&
    !jobWebsocket.current
  ) {
    const websocketUrl = `${
      window.location.protocol === "https:" ? "wss" : "ws"
    }://${window.location.host}/${WEBSOCKET_JOBS_URI}/${jobId}`;
    console.debug(`connect to websocket API: ${websocketUrl}`);
    jobWebsocket.current = new WebSocket(websocketUrl);
    jobWebsocket.current.onopen = (jobWsData) => {
      console.debug("ws opened:");
      console.debug(jobWsData);
    };
    jobWebsocket.current.onclose = (jobWsData) => {
      console.debug("ws closed:");
      console.debug(jobWsData);
    };
    jobWebsocket.current.onmessage = (jobWsData) => {
      console.debug("ws received:");
      console.debug(jobWsData);
      const wsJobData = JSON.parse(jobWsData.data);
      if (Object.values(JobFinalStatuses).includes(wsJobData.status)) {
        jobWebsocket.current.close(1000);
      }
      setData({ ...data, job: wsJobData });
    };
    jobWebsocket.current.onerror = (jobWsData) => {
      console.debug("ws error:");
      console.debug(jobWsData);
    };
  }

  // In case the job terminated and it's not to notify, it means the user waited the result, notification is not needed.
  React.useEffect(() => {
    if (!jobIsRunning && !toNotify) {
      setNotified(true);
    }
  }, [jobIsRunning, toNotify]);

  // notify the user when the job ends, he left the web page and we didn't notified the user before.
  if (!jobIsRunning && toNotify && !notified) {
    generateJobNotification(data.job.observable_name, data.job.id);
    setNotified(true);
  }

  console.debug("JobResult - data", data);

  return (
    <Loader
      loading={dataIsDownloading}
      error={jobError}
      render={() => (
        <JobOverview
          isRunningJob={jobIsRunning}
          job={data.job}
          relatedInvestigationNumber={data.relatedInvestigationNumber}
          refetch={refetchJob}
          section={section}
          subSection={subSection}
        />
      )}
    />
  );
}
