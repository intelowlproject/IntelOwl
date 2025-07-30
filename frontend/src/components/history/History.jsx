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
import { useGuideContext } from "../../contexts/GuideContext";
import { createInvestigation } from "../investigations/result/investigationApi";
import { datetimeFormatStr, HistoryPages } from "../../constants/miscConst";
import { UserEventModal } from "../userEvents/UserEventModal";

const HistoryTable = React.lazy(() => import("./HistoryTable"));

export default function History() {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams, _] = useSearchParams();

  const pageType = location?.pathname?.split("/")[2];
  let startTimeString = "event_date__gte";
  let endTimeString = "event_date__lte";
  let createButtonTitle = "New evaluation";

  if (pageType === HistoryPages.JOBS) {
    startTimeString = "received_request_time__gte";
    endTimeString = "received_request_time__lte";
    createButtonTitle = "Create job";
  } else if (pageType === HistoryPages.INVESTIGAITONS) {
    startTimeString = "start_time__gte";
    endTimeString = "start_time__lte";
    createButtonTitle = "Create Investigation";
  }

  const startTimeParam = searchParams.get(startTimeString);
  const endTimeParam = searchParams.get(endTimeString);

  const { guideState, setGuideState } = useGuideContext();

  React.useEffect(() => {
    if (guideState.tourActive) {
      setTimeout(() => {
        setGuideState({ run: true, stepIndex: 7 });
      }, 200);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const [showUserEventModal, setShowUserEventModal] = React.useState(false);

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
      setShowUserEventModal(!showUserEventModal);
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
        &nbsp;{createButtonTitle}
      </Button>
      {showUserEventModal && (
        <UserEventModal
          toggle={setShowUserEventModal}
          isOpen={showUserEventModal}
        />
      )}
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
            to={`/history/user-events?event_date__gte=${encodeURIComponent(
              format(startTimeParam, datetimeFormatStr),
            )}&event_date__lte=${encodeURIComponent(
              format(endTimeParam, datetimeFormatStr),
            )}&ordering=-date`}
          >
            <span id="user-events" className="d-flex-center">
              <GrDocumentUser />
              &nbsp;Artifacts evaluations
            </span>
          </RRNavLink>
        </NavItem>
        <NavItem
          className="border-dark"
          style={{ borderRightStyle: "solid", borderRightWidth: "1px" }}
        >
          <RRNavLink
            className="nav-link"
            to={`/history/user-ip-wildcard-events?event_date__gte=${encodeURIComponent(
              format(startTimeParam, datetimeFormatStr),
            )}&event_date__lte=${encodeURIComponent(
              format(endTimeParam, datetimeFormatStr),
            )}&ordering=-date`}
          >
            <span id="user-ip-events" className="d-flex-center">
              <GrDocumentUser />
              &nbsp;Ip wildcard evaluations
            </span>
          </RRNavLink>
        </NavItem>
        <NavItem
          className="border-dark"
          style={{ borderRightStyle: "solid", borderRightWidth: "1px" }}
        >
          <RRNavLink
            className="nav-link"
            to={`/history/user-domain-wildcard-events?event_date__gte=${encodeURIComponent(
              format(startTimeParam, datetimeFormatStr),
            )}&event_date__lte=${encodeURIComponent(
              format(endTimeParam, datetimeFormatStr),
            )}&ordering=-date`}
          >
            <span id="user-domain-events" className="d-flex-center">
              <GrDocumentUser />
              &nbsp;Domain wildcard evaluations
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
            <HistoryTable
              pageType={pageType}
              startTimeString={startTimeString}
              endTimeString={endTimeString}
            />
          </Suspense>
        </TabPane>
      </TabContent>
    </>
  );
}
