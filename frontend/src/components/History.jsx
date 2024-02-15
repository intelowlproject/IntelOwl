import React, { Suspense } from "react";
import { RiFileListFill } from "react-icons/ri";
import { DiGitMerge } from "react-icons/di";
import { BsFillPlusCircleFill } from "react-icons/bs";
import { Button, Col } from "reactstrap";
import { RouterTabs, FallBackLoading } from "@certego/certego-ui";
import { useNavigate, useLocation } from "react-router-dom";

import { createAnalysis } from "./analysis/result/analysisApi";

const JobsTable = React.lazy(() => import("./jobs/table/JobsTable"));
const AnalysisTable = React.lazy(() =>
  import("./analysis/table/AnalysisTable"),
);
/*
lazy imports to enable code splitting
*/

const historyRoutes = [
  {
    key: "history-jobs",
    location: "jobs",
    Title: () => (
      <span id="Jobs">
        <RiFileListFill />
        &nbsp;Jobs
      </span>
    ),
    Component: () => (
      <Suspense fallback={<FallBackLoading />}>
        <JobsTable />
      </Suspense>
    ),
  },
  {
    key: "history-analysis",
    location: "analysis",
    Title: () => (
      <span id="Analysis">
        <DiGitMerge />
        &nbsp;Analysis
      </span>
    ),
    Component: () => (
      <Suspense fallback={<FallBackLoading />}>
        <AnalysisTable />
      </Suspense>
    ),
  },
];

export default function History() {
  const navigate = useNavigate();
  const location = useLocation();
  const isJobsTablePage = location?.pathname.includes("jobs");

  const onClick = async () => {
    if (isJobsTablePage) {
      navigate("/scan");
    } else {
      try {
        const analysisId = await createAnalysis();
        if (analysisId) navigate(`/analysis/${analysisId}`);
      } catch {
        // handle inside createAnalysis
      }
    }
  };

  const createButton = (
    <Col className="d-flex justify-content-end">
      <Button id="createbutton" size="sm" color="darker" onClick={onClick}>
        <BsFillPlusCircleFill />
        &nbsp;Create {isJobsTablePage ? "job" : "analysis"}
      </Button>
    </Col>
  );
  return <RouterTabs routes={historyRoutes} extraNavComponent={createButton} />;
}
