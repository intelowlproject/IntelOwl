import React from "react";
import { useHistory } from "react-router-dom";
import { Button } from "reactstrap";

import useRecentScansStore from "../../../stores/useRecentScansStore";

export default function RecentScans() {
  const { jobIdStatusMap, } = useRecentScansStore();

  const history = useHistory();

  const onClick = React.useCallback(
    (jobId) => {
      history.push(`/jobs/${jobId}`);
    },
    [history]
  );

  return (
    <div className="d-flex-start-start flex-wrap">
      {Object.entries(jobIdStatusMap).map(([jobId, status]) => (
        <Button
          key={`recentscans__${jobId}`}
          color={status}
          size="sm"
          className="mb-2 mr-2"
          onClick={() => onClick(jobId)}
        >
          Job #{jobId}
        </Button>
      ))}
    </div>
  );
}
