import React from "react";
import PropTypes from "prop-types";
import { RiFileListFill, RiNodeTree } from "react-icons/ri";
import { BsFillPlusCircleFill } from "react-icons/bs";
import { GrDocumentUser } from "react-icons/gr";
import { Button, Col, Nav, NavItem } from "reactstrap";
import { useNavigate, NavLink as RRNavLink } from "react-router-dom";
import { fromZonedTime } from "date-fns-tz";

import { createInvestigation } from "../investigations/result/investigationApi";
import { HistoryPages, localTimezone } from "../../constants/miscConst";
import { UserEventModal } from "../userEvents/UserEventModal";

export function HistoryNav({ pageType, startTimeParam, endTimeParam }) {
  const navigate = useNavigate();

  let createButtonTitle = "New evaluation";
  if (pageType === HistoryPages.JOB) {
    createButtonTitle = "Create job";
  } else if (pageType === HistoryPages.INVESTIGAITON) {
    createButtonTitle = "Create Investigation";
  }

  const startDate = fromZonedTime(startTimeParam, localTimezone).toISOString();
  const endDate = fromZonedTime(endTimeParam, localTimezone).toISOString();

  const [showUserEventModal, setShowUserEventModal] = React.useState(false);

  const onClick = async () => {
    if (pageType === HistoryPages.JOB) {
      navigate("/scan");
    } else if (pageType === HistoryPages.INVESTIGAITON) {
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
    <Nav className="nav-tabs">
      <NavItem
        className="border-dark"
        style={{ borderRightStyle: "solid", borderRightWidth: "1px" }}
      >
        <RRNavLink
          className="nav-link"
          to={`/history/jobs?received_request_time__gte=${encodeURIComponent(
            startDate,
          )}&received_request_time__lte=${encodeURIComponent(
            endDate,
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
            startDate,
          )}&start_time__lte=${encodeURIComponent(
            endDate,
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
            startDate,
          )}&event_date__lte=${encodeURIComponent(endDate)}&ordering=-date`}
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
            startDate,
          )}&event_date__lte=${encodeURIComponent(endDate)}&ordering=-date`}
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
            startDate,
          )}&event_date__lte=${encodeURIComponent(endDate)}&ordering=-date`}
        >
          <span id="user-domain-events" className="d-flex-center">
            <GrDocumentUser />
            &nbsp;Domain wildcard evaluations
          </span>
        </RRNavLink>
      </NavItem>
      {createButton}
    </Nav>
  );
}

HistoryNav.propTypes = {
  pageType: PropTypes.string.isRequired,
  startTimeParam: PropTypes.string.isRequired,
  endTimeParam: PropTypes.string.isRequired,
};
