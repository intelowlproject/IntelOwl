import React, { useEffect } from "react";
import useTitle from "react-use/lib/useTitle";
import { useParams } from "react-router-dom";

import { Loader } from "@certego/certego-ui";
import axios from "axios";
import { WEBSOCKET_JOBS_URI, JOB_BASE_URI } from "../../../constants/apiURLs";
import { JobOverview } from "./JobOverview";

import {
  generateJobNotification,
  setNotificationFavicon,
} from "../notifications";

export default function JobResult() {
  console.debug("JobResult rendered!");

  const [initialLoading, setInitialLoading] = React.useState(true);
  const [initialError, setInitialError] = React.useState("");
  const [job, setJob] = React.useState(undefined);
  // this state var is used to check if we notified the user, in this way we avoid to notify more than once
  const [notified, setNotified] = React.useState(false);
  // this state var is used to check if the user changed page, in case he waited the result on the page we avoid the notification
  const [toNotify, setToNotify] = React.useState(false);

  // from props
  const params = useParams();
  const jobId = params.id;
  const { section } = params;
  const { subSection } = params;

  const jobIsRunning =
    job === undefined ||
    [
      "pending",
      "running",
      "analyzers_running",
      "connectors_running",
      "pivots_running",
      "visualizers_running",
      "analyzers_completed",
      "connectors_completed",
      "pivots_completed",
      "visualizers_completed",
    ].includes(job.status);

  console.debug(
    `JobResult - initialLoading: ${initialLoading}, jobIsRunning: ${jobIsRunning}, ` +
      `notified: ${notified}, toNotify: ${toNotify}`,
  );

  const getJob = () => axios.get(`${JOB_BASE_URI}/${jobId}`);
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
    getJob()
      .then((response) => setJob(response.data))
      .catch((err) => setInitialError(err));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // page title
  useTitle(
    `IntelOwl | Job (#${jobId}, ${
      // eslint-disable-next-line no-nested-ternary
      job ? (job.is_sample ? job.file_name : job.observable_name) : ""
    })`,
    { restoreOnUnmount: true },
  );

  useEffect(() => {
    /* this is required because the first loading we don't have job data
      and this is a problem for JobOverview that needs the UI sections names
      so the first time the page has a spinner, after the first request
      the spinner will be moved in the sections.
    */
    if (job) setInitialLoading(false);
  }, [job]);

  /* SETUP WS:
  only in case the first request didn't get the job in a final status.
  use ws with useRef to avoid to create a ws each render AND create the ws.
  only in the last page (section and subSection) or we will create 3 ws, one for each redirect:
  jobs/1 -> jobs/1/visualizer -> jobs/1/visualizer/loading
  */
  const jobWebsocket = React.useRef();
  if (job && jobIsRunning && section && subSection && !jobWebsocket.current) {
    const websocketUrl = `${
      window.location.protocol === "https:" ? "wss" : "ws"
    }://${window.location.hostname}/${WEBSOCKET_JOBS_URI}/${jobId}`;
    console.debug(`connect to websocket API: ${websocketUrl}`);
    jobWebsocket.current = new WebSocket(websocketUrl);
    jobWebsocket.current.onopen = (data) => {
      console.debug("ws opened:");
      console.debug(data);
    };
    jobWebsocket.current.onclose = (data) => {
      console.debug("ws closed:");
      console.debug(data);
    };
    jobWebsocket.current.onmessage = (data) => {
      console.debug("ws received:");
      console.debug(data);
      const jobData = JSON.parse(data.data);
      setJob(jobData);
    };
    jobWebsocket.current.onerror = (data) => {
      console.debug("ws error:");
      console.debug(data);
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
    generateJobNotification(job.observable_name, job.id);
    setNotified(true);
  }

  return (
    <Loader
      loading={initialLoading}
      error={initialError}
      render={() => (
        <JobOverview
          isRunningJob={jobIsRunning}
          job={job}
          section={section}
          subSection={subSection}
        />
      )}
    />
  );
}
