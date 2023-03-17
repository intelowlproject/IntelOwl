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
  const [canNotify, setCanNotify] = React.useState(false);

  // from props
  const params = useParams();
  const jobId = params.id;

  // API to download the job data
  const [{ data: job, loading, error }, refetch] = useAxios({
    url: `${JOB_BASE_URI}/${jobId}`,
  });

  const refetchWithNotification = () => {
    setCanNotify(true);
    refetch();
  };

  // HTTP polling only in case the job is running
  useInterval(
    refetchWithNotification,
    isRunning ? 5 * 1000 : null // 5 seconds
  );

  // every time the job data are downloaded we check fi it terminated or not
  React.useEffect(
    () =>
      setIsRunning(
        job === undefined || ["pending", "running"].includes(job.status)
      ),
    [job]
  );

  /* notify the user when the job ends and we did at least one refetch call:
  in this way we avoid to annoy the user with the notifications in case he open terminated job or run jobs that terminated 
  before he change page.
  */
  if (canNotify && !isRunning) {
    generateJobNotification(job.observable_name, job.id);
  }

  // initial loading (spinner)
  React.useEffect(() => {
    if (!loading) setInitialLoading(false);
  }, [loading]);

  // add a focus listener: when the browser tab get the focus we remove the notification favicon
  React.useEffect(() => {
    window.addEventListener("focus", () => setNotificationFavicon(false));
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
