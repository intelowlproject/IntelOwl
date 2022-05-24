import React from "react";
import PropTypes from "prop-types";
import useAxios from "axios-hooks";
import useTitle from "react-use/lib/useTitle";
import useInterval from "react-use/lib/useInterval";
import { useParams } from "react-router-dom";

import { Loader } from "@certego/certego-ui";
import { JOB_BASE_URI } from "../../../constants/api";
import { JobOverview } from "./utils";

export default function JobResult() {
  console.debug("JobResult rendered!");

  // local state
  const [initialLoading, setInitialLoading] = React.useState(true);

  // from props
  const params = useParams();
  const jobId = params.id;
  console.log(jobId);

  // API
  const [{ data: job, loading, error, }, refetch] = useAxios({
    url: `${JOB_BASE_URI}/${jobId}`,
  });

  // HTTP poll and check status until finish
  const isRunning =
    job === undefined || ["pending", "running"].includes(job.status);
  useInterval(
    refetch,
    isRunning ? 5 * 1000 : null // 5 seconds
  );

  // initial loading (spinner)
  React.useEffect(() => {
    if (!loading) setInitialLoading(false);
  }, [loading]);

  // page title
  useTitle(
    `IntelOwl | Job (#${jobId}, ${
      // eslint-disable-next-line no-nested-ternary
      job ? (job.is_sample ? job.file_name : job.observable_name) : ""
    })`,
    { restoreOnUnmount: true, }
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
