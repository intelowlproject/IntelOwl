import React from "react";
import PropTypes from "prop-types";
import { Col, Row, Container } from "reactstrap";
import { MdEdit } from "react-icons/md";
import { useLocation } from "react-router-dom";

import { IconButton } from "@certego/certego-ui";
import { StatusIcon } from "../../common/icon/StatusIcon";

import { AnalysisInfoCard } from "./AnalysisInfoCard";
import { AnalysisIsRunningAlert } from "./AnalysisIsRunningAlert";
import { AnalysisActionsBar } from "./AnalysisActionBar";

export function AnalysisOverview({ isRunningAnalysis, analysis }) {
  console.debug("AnalysisOverview rendered");

  // state
  const location = useLocation();
  console.debug(
    `location pathname: ${location.pathname}, state: ${JSON.stringify(
      location?.state,
    )}`,
  );

  return (
    <Container fluid>
      {/* bar with analysis id and utilities buttons */}
      <Row
        className="g-0 d-flex-between-end align-items-center"
        id="utilitiesRow"
      >
        <Col>
          <h2>
            <span className="me-2 text-secondary">Analysis #{analysis.id}</span>
            <StatusIcon status={analysis.status} className="small" />
          </h2>
        </Col>
        <Col className="d-flex justify-content-end mt-1">
          <AnalysisActionsBar analysis={analysis} />
        </Col>
      </Row>
      {/* analysis metadata card */}
      <Row className="g-0">
        <Col>
          <AnalysisInfoCard analysis={analysis} />
        </Col>
      </Row>
      <Row className="g-0 mt-3">
        <div className="mb-2">
          <span className="fw-bold text-light">Description</span>
          <IconButton
            id="edit-analysis-description"
            Icon={MdEdit}
            size="sm"
            color=""
            className="me-2 text-secondary"
            onClick={() => null}
            title="Edit description"
            titlePlacement="top"
          />
          <div
            className={`bg-dark p-1 ${
              analysis.description ? "text-light" : "text-gray"
            }`}
            style={{ minHeight: "100px" }}
          >
            {analysis.description ? analysis.description : "No description"}
          </div>
        </div>
        {isRunningAnalysis && (
          <Row>
            <AnalysisIsRunningAlert analysis={analysis} />
          </Row>
        )}
      </Row>
    </Container>
  );
}

AnalysisOverview.propTypes = {
  isRunningAnalysis: PropTypes.bool.isRequired,
  analysis: PropTypes.object.isRequired,
};
