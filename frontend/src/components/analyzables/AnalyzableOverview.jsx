import React from "react";
import PropTypes from "prop-types";
import { Col, Row, Container } from "reactstrap";

import { AnalyzableActionsBar } from "./AnalyzableActionBar";
import { AnalyzableInfoCard } from "./AnalyzableInfoCard";

export function AnalyzableOverview({ analyzable }) {
  console.debug("AnalyzableOverview rendered");

  return (
    <Container fluid>
      {/* bar with analyzable id and utilities buttons */}
      <Row
        className="g-0 d-flex-between-end align-items-center"
        id="utilitiesRow"
      >
        <Col>
          <h2 className="d-flex align-items-center">
            <span className="me-2 text-secondary">
              Analyzable #{analyzable.id}
            </span>
          </h2>
        </Col>
        <Col md={8} className="d-flex justify-content-end mt-1">
          <AnalyzableActionsBar analyzable={analyzable} />
        </Col>
      </Row>
      {/* analyzable metadata card */}
      <Row className="g-0">
        <Col>
          <AnalyzableInfoCard analyzable={analyzable} />
        </Col>
      </Row>
    </Container>
  );
}

AnalyzableOverview.propTypes = {
  analyzable: PropTypes.object.isRequired,
};
