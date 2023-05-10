import React from "react";
import useAxios from "axios-hooks";
import useTitle from "react-use/lib/useTitle";
import useInterval from "react-use/lib/useInterval";
import { useParams } from "react-router-dom";

import { Loader } from "@certego/certego-ui";
import { JOB_BASE_URI } from "../../../constants/api";
import { JobOverview } from "./utils";

import {
  generateJobNotification,
  setNotificationFavicon,
} from "../notifications";

export default function JobResult() {
  console.debug("JobResult rendered!");

  // local state
  const [initialLoading, setInitialLoading] = React.useState(true);
  const [isRunning, setIsRunning] = React.useState(false);
  // this state var is used to check if we notified the user, in this way we avoid to notify more than once
  const [notified, setNotified] = React.useState(false);
  // this state var is used to check if the user changed page, in case he waited the result on the page we avoid the notification
  const [toNotify, setToNotify] = React.useState(false);

  // from props
  const params = useParams();
  const jobId = params.id;

  // API to download the job data
  const [{ data: job, loading, error }, refetch] = useAxios({
    url: `${JOB_BASE_URI}/${jobId}`,
  });

  // in case the job is not running and started (the job is not undefined) it means it terminated.
  const jobTerminated = job !== undefined && !isRunning;

  console.debug(
    `JobResult - initialLoading: ${initialLoading}, isRunning: ${isRunning}, ` +
      `notified: ${notified}, toNotify: ${toNotify}, jobTerminated: ${jobTerminated}`
  );

  // HTTP polling only in case the job is running
  useInterval(
    refetch,
    isRunning ? 5 * 1000 : null // 5 seconds
  );

  // every time the job data are downloaded we check if it terminated or not
  React.useEffect(
    () =>
      setIsRunning(
        job === undefined || ["pending", "running"].includes(job.status)
      ),
    [job]
  );

  // In case the job terminated and it's not to notify, it means the user waited the result, notification is not needed.
  React.useEffect(() => {
    if (jobTerminated && !toNotify) {
      setNotified(true);
    }
  }, [isRunning, jobTerminated, toNotify]);

  // notify the user when the job ends, he left the web page and we didn't notified the user before.
  if (jobTerminated && toNotify && !notified) {
    generateJobNotification(job.observable_name, job.id);
    setNotified(true);
  }

  // initial loading (spinner)
  React.useEffect(() => {
    if (!loading) setInitialLoading(false);
  }, [loading]);

  /* add a focus listener:
  when gain focus set it has been notified and reset the favicon
  when lost focus (blur) we set we can notify the user
  */
  React.useEffect(() => {
    window.addEventListener("focus", () => {
      setNotificationFavicon(false);
      setToNotify(false);
    });
    window.addEventListener("blur", () => setToNotify(true));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // page title
  useTitle(
    `IntelOwl | Job (#${jobId}, ${
      // eslint-disable-next-line no-nested-ternary
      job ? (job.is_sample ? job.file_name : job.observable_name) : ""
    })`,
    { restoreOnUnmount: true }
  );

  return (
    <Loader
      loading={initialLoading}
      error={error}
      render={() => (
        <JobOverview isRunningJob={isRunning} job={job} refetch={refetch} />
      )}
    />
  );
}
