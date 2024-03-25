import React, { Suspense } from "react";
import { RiFileListFill } from "react-icons/ri";
import { DiGitMerge } from "react-icons/di";
import { BsFillPlusCircleFill } from "react-icons/bs";
import { Button, Col } from "reactstrap";
import { RouterTabs, FallBackLoading } from "@certego/certego-ui";
import { useNavigate, useLocation } from "react-router-dom";

import { createInvestigation } from "./investigations/result/investigationApi";

const JobsTable = React.lazy(() => import("./jobs/table/JobsTable"));
const InvestigationsTable = React.lazy(
  () => import("./investigations/table/InvestigationsTable"),
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
    key: "history-investigations",
    location: "investigations",
    Title: () => (
      <span id="Investigations">
        <DiGitMerge />
        &nbsp;Investigations
      </span>
    ),
    Component: () => (
      <Suspense fallback={<FallBackLoading />}>
        <InvestigationsTable />
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
        const investigationId = await createInvestigation();
        if (investigationId) navigate(`/investigation/${investigationId}`);
      } catch {
        // handle inside createInvestigation
      }
    }
  };

  const createButton = (
    <Col className="d-flex justify-content-end">
      <Button id="createbutton" size="sm" color="darker" onClick={onClick}>
        <BsFillPlusCircleFill />
        &nbsp;Create {isJobsTablePage ? "job" : "investigation"}
      </Button>
    </Col>
  );
  return <RouterTabs routes={historyRoutes} extraNavComponent={createButton} />;
}
