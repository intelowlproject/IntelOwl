import React, { Suspense } from "react";
import { RiFileListFill, RiNodeTree } from "react-icons/ri";
import { BsFillPlusCircleFill } from "react-icons/bs";
import { GrDocumentUser } from "react-icons/gr";
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
import { datetimeFormatStr, HistoryPages } from "../constants/miscConst";

const JobsTable = React.lazy(() => import("./jobs/table/JobsTable"));
const InvestigationsTable = React.lazy(
  () => import("./investigations/table/InvestigationsTable"),
);
const UserReportsTable = React.lazy(
  () => import("./userEvents/table/UserReportsTable"),
);

export default function History() {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams, _] = useSearchParams();

  let pageType;
  let startTimeParam;
  let endTimeParam;

  if (location?.pathname.includes(HistoryPages.JOBS)) {
    pageType = HistoryPages.JOBS;
    startTimeParam = searchParams.get("received_request_time__gte");
    endTimeParam = searchParams.get("received_request_time__lte");
  } else if (location?.pathname.includes(HistoryPages.INVESTIGAITONS)) {
    pageType = HistoryPages.INVESTIGAITONS;
    startTimeParam = searchParams.get("start_time__gte");
    endTimeParam = searchParams.get("start_time__lte");
  } else {
    pageType = HistoryPages.USER_REPORTS;
    startTimeParam = searchParams.get("date__gte");
    endTimeParam = searchParams.get("date__lte");
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
    if (pageType === HistoryPages.JOBS) {
      navigate("/scan");
    } else if (pageType === HistoryPages.INVESTIGAITONS) {
      try {
        const investigationId = await createInvestigation();
        if (investigationId) navigate(`/investigation/${investigationId}`);
      } catch {
        // handle inside createInvestigation
      }
    } else {
      // !!!! da aggiungere l'apertura del modale una volta realizzato
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
        &nbsp;Create {pageType.substring(0, pageType.length - 1)}
      </Button>
    </Col>
  );

  return (
    <>
      <Nav className="nav-tabs">
        <NavItem
          className="border-dark"
          style={{ borderRightStyle: "solid", borderRightWidth: "1px" }}
        >
          <RRNavLink
            className="nav-link"
            to={`/history/jobs?received_request_time__gte=${encodeURIComponent(
              format(startTimeParam, datetimeFormatStr),
            )}&received_request_time__lte=${encodeURIComponent(
              format(endTimeParam, datetimeFormatStr),
            )}&ordering=-received_request_time`}
          >
            <span id="Jobs" className="d-flex-center">
              <RiFileListFill />
              &nbsp;Jobs
            </span>
          </RRNavLink>
        </NavItem>
        <NavItem
          className="border-dark"
          style={{ borderRightStyle: "solid", borderRightWidth: "1px" }}
        >
          <RRNavLink
            className="nav-link"
            to={`/history/investigations?start_time__gte=${encodeURIComponent(
              format(startTimeParam, datetimeFormatStr),
            )}&start_time__lte=${encodeURIComponent(
              format(endTimeParam, datetimeFormatStr),
            )}&ordering=-start_time`}
          >
            <span id="investigations" className="d-flex-center">
              <RiNodeTree />
              &nbsp;Investigations
            </span>
          </RRNavLink>
        </NavItem>
        <NavItem
          className="border-dark"
          style={{ borderRightStyle: "solid", borderRightWidth: "1px" }}
        >
          <RRNavLink
            className="nav-link"
            to={`/history/user-reports?date__gte=${encodeURIComponent(
              format(startTimeParam, datetimeFormatStr),
            )}&date__lte=${encodeURIComponent(
              format(endTimeParam, datetimeFormatStr),
            )}&ordering=-date`}
          >
            <span id="user-reports" className="d-flex-center">
              <GrDocumentUser />
              &nbsp;User Reports
            </span>
          </RRNavLink>
        </NavItem>
        {createButton}
      </Nav>
      {/* This is way to generate only the table the user wants this allow to save:
       * requests to the backend
       * loading time
       * avoid error when request job page 3 and jobs has for ex 6 pages and investigations 2 */}
      <TabContent activeTab={pageType}>
        <TabPane tabId={pageType} className="mt-2">
          <Suspense fallback={<FallBackLoading />}>
            {pageType === HistoryPages.JOBS && <JobsTable />}
            {pageType === HistoryPages.INVESTIGAITONS && (
              <InvestigationsTable />
            )}
            {pageType === HistoryPages.USER_REPORTS && <UserReportsTable />}
          </Suspense>
        </TabPane>
      </TabContent>
    </>
  );
}
