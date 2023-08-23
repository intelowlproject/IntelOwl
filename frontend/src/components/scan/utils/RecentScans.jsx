import React from "react";
import { useNavigate } from "react-router-dom";
import { Card, CardHeader, CardBody } from "reactstrap";
import useRecentScansStore from "../../../stores/useRecentScansStore";

const md5 = require("md5");

export default function RecentScans(observableName) {
  const { jobIdStatusMap } = useRecentScansStore();

  console.debug(observableName);
  if (observableName !== "") {
    console.debug(md5(observableName));
  }

  const navigate = useNavigate();

  const onClick = React.useCallback(
    (jobId) => {
      navigate(`/jobs/${jobId}`);
    },
    [navigate],
  );

  return (
    <div>
      <h5 className="fw-bold my-4">Recent Scans</h5>
      {Object.entries(jobIdStatusMap).map(([jobId, status]) => (
        <Card className="border-dark mb-2" onClick={() => onClick(jobId)}>
          <CardHeader className="bg-dark text-center p-0">
            Job #{jobId}
          </CardHeader>
          <CardBody className="bg-darker p-2">{status}</CardBody>
        </Card>
      ))}
    </div>
  );
}
