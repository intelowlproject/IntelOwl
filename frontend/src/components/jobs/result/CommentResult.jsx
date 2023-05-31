import React from "react";
import useAxios from "axios-hooks";
import useTitle from "react-use/lib/useTitle";
import { useParams } from "react-router-dom";
import { Loader } from "@certego/certego-ui";

import { JOB_BASE_URI } from "../../../constants/api";

import { CommentOverview } from "./utils";

export default function CommentResult() {
  console.debug("CommentResult rendered!");

  // local state
  const [initialLoading, setInitialLoading] = React.useState(true);

  // from props
  const params = useParams();
  const jobId = params.id;

  // API
  const [{ data: job, loading, error }, refetch] = useAxios({
    url: `${JOB_BASE_URI}/${jobId}`,
  });

  // initial loading (spinner)
  React.useEffect(() => {
    if (!loading) setInitialLoading(false);
  }, [loading, job]);

  // page title
  useTitle(`IntelOwl | Comments (#${jobId})`, { restoreOnUnmount: true });

  return (
    <Loader
      loading={initialLoading}
      error={error}
      render={() => <CommentOverview job={job} refetchComments={refetch} />}
    />
  );
}
