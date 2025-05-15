import React from "react";
import useAxios from "axios-hooks";
import useTitle from "react-use/lib/useTitle";
import { useParams } from "react-router-dom";

import { Loader } from "@certego/certego-ui";
import { ANALYZABLES_URI } from "../../constants/apiURLs";
import { AnalyzableOverview } from "./AnalyzableOverview";

export default function AnalyzableResult() {
  console.debug("AnalyzableResult rendered!");

  // local state
  const [initialLoading, setInitialLoading] = React.useState(true);

  // from props
  const params = useParams();
  const analyzableId = params.id;

  // API to download the analyzable data
  const [{ data: analyzable, loading, error }] = useAxios({
    url: `${ANALYZABLES_URI}/${analyzableId}`,
  });

  // initial loading (spinner)
  React.useEffect(() => {
    if (!loading) setInitialLoading(false);
  }, [loading]);

  // page title
  useTitle(`IntelOwl | Analyzable (#${analyzableId})`, {
    restoreOnUnmount: true,
  });

  return (
    <Loader
      loading={initialLoading}
      error={error}
      render={() => <AnalyzableOverview analyzable={analyzable} />}
    />
  );
}
