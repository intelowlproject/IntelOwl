import React from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "reactstrap";

import useRecentScansStore from "../../../stores/useRecentScansStore";

export default function RecentScans() {
  const { jobIdStatusMap, } = useRecentScansStore();

  const navigate = useNavigate();

  const onClick = React.useCallback(
    (jobId) => {
      navigate(`/jobs/${jobId}`);
    },
    [navigate]
  );

  return (
    <div className="d-flex-start-start flex-wrap">
      {Object.entries(jobIdStatusMap).map(([jobId, status]) => (
        <Button
          key={`recentscans__${jobId}`}
          color={status}
          size="sm"
          className="mb-2 me-2"
          onClick={() => onClick(jobId)}
        >
          Job #{jobId}
        </Button>
      ))}
    </div>
  );
}
