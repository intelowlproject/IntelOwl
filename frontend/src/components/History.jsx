import React, { Suspense } from "react";
import { RiFileListFill } from "react-icons/ri";
import { DiGitMerge } from "react-icons/di";
import { BsFillPlusCircleFill } from "react-icons/bs";
import { Button, Col, Nav, NavItem, TabContent, TabPane } from "reactstrap";
import {
  useNavigate,
  useLocation,
  useSearchParams,
  NavLink as RRNavLink,
} from "react-router-dom";
import { format } from "date-fns-tz";

import { FallBackLoading } from "@certego/certego-ui";
import { useGuideContext } from "../contexts/GuideContext";
import { createInvestigation } from "./investigations/result/investigationApi";
import { datetimeFormatStr } from "../constants/miscConst";

const JobsTable = React.lazy(() => import("./jobs/table/JobsTable"));
const InvestigationsTable = React.lazy(
  () => import("./investigations/table/InvestigationsTable"),
);

export default function History() {
  const navigate = useNavigate();
  const location = useLocation();
  const isJobsTablePage = location?.pathname.includes("jobs");

  const [searchParams, _] = useSearchParams();

  let startTimeParam;
  let endTimeParam;

  if (isJobsTablePage) {
    startTimeParam = searchParams.get("received_request_time__gte");
    endTimeParam = searchParams.get("received_request_time__lte");
  } else {
    startTimeParam = searchParams.get("start_time__gte");
    endTimeParam = searchParams.get("start_time__lte");
  }

  const { guideState, setGuideState } = useGuideContext();

  React.useEffect(() => {
    if (guideState.tourActive) {
      setTimeout(() => {
        setGuideState({ run: true, stepIndex: 7 });
      }, 200);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

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
      <Button
        id="createbutton"
        className="d-flex align-items-center"
        size="sm"
        color="darker"
        onClick={onClick}
      >
        <BsFillPlusCircleFill />
        &nbsp;Create {isJobsTablePage ? "job" : "investigation"}
      </Button>
    </Col>
  );

  return (
    <>
      <Nav className="nav-tabs">
        <NavItem>
          <RRNavLink
            className="nav-link"
            to={`/history/jobs?received_request_time__gte=${encodeURIComponent(
              format(startTimeParam, datetimeFormatStr),
            )}&received_request_time__lte=${encodeURIComponent(
              format(endTimeParam, datetimeFormatStr),
            )}`}
          >
            <span id="Jobs">
              <RiFileListFill />
              &nbsp;Jobs
            </span>
          </RRNavLink>
        </NavItem>
        <NavItem>
          <RRNavLink
            className="nav-link"
            to={`/history/investigations?start_time__gte=${encodeURIComponent(
              format(startTimeParam, datetimeFormatStr),
            )}&start_time__lte=${encodeURIComponent(
              format(endTimeParam, datetimeFormatStr),
            )}`}
          >
            <span id="investigations">
              <DiGitMerge />
              &nbsp;Investigations
            </span>
          </RRNavLink>
        </NavItem>
        {createButton}
      </Nav>
      {/* This is way to generate only the table the user wants this allow to save:
       * requests to the backend
       * loading time
       * avoid error when request job page 3 and jobs has for ex 6 pages and investigations 2 */}
      <TabContent activeTab={isJobsTablePage ? "jobs" : "investigations"}>
        <TabPane tabId={isJobsTablePage ? "jobs" : "investigations"}>
          <Suspense fallback={<FallBackLoading />}>
            {isJobsTablePage ? <JobsTable /> : <InvestigationsTable />}
          </Suspense>
        </TabPane>
      </TabContent>
    </>
  );
}
