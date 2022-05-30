import React from "react";
import PropTypes from "prop-types";
import { Col, Row, Badge, Container } from "reactstrap";

import { GoBackButton, Tabs } from "@certego/certego-ui";

import { AnalyzersReportTable, ConnectorsReportTable } from "./tables";
import { JobInfoCard, JobIsRunningAlert, JobActionsBar } from "./sections";
import { StatusIcon } from "../../../common";

export default function JobOverview({ isRunningJob, job, refetch }) {
  const tabTitles = React.useMemo(
    () => [
      <div className="d-flex-center">
        <strong>Analyzers Report</strong>
        <Badge className="ms-2">
          {job.analyzers_to_execute?.length} /&nbsp;
          {job.analyzers_requested?.length || "all"}
        </Badge>
      </div>,
      <div className="d-flex-center">
        <strong>Connectors Report</strong>
        <Badge className="ms-2">
          {job.connectors_to_execute?.length} /&nbsp;
          {job.connectors_requested?.length || "all"}
        </Badge>
      </div>,
    ],
    [job]
  );
  const tabRenderables = React.useMemo(
    () => [
      () => <AnalyzersReportTable job={job} refetch={refetch} />,
      () => <ConnectorsReportTable job={job} refetch={refetch} />,
    ],
    [job, refetch]
  );

  return (
    <Container fluid>
      <Row className="g-0 d-flex-between-end">
        <Col>
          <GoBackButton onlyIcon color="gray" />
          <h2>
            <span className="me-2 text-secondary">Job #{job.id}</span>
            <StatusIcon status={job.status} className="small" />
          </h2>
        </Col>
        <Col className="d-flex justify-content-end">
          <JobActionsBar job={job} />
        </Col>
      </Row>
      <Row className="g-0">
        <Col>
          <JobInfoCard job={job} />
        </Col>
      </Row>
      {isRunningJob && (
        <Row>
          <JobIsRunningAlert job={job} />
        </Row>
      )}
      <Row className="g-0 mt-3">
        <Col>
          <Tabs
            tabTitles={tabTitles}
            renderables={tabRenderables}
            className="mx-auto"
          />
        </Col>
      </Row>
    </Container>
  );
}

JobOverview.propTypes = {
  isRunningJob: PropTypes.bool.isRequired,
  job: PropTypes.object.isRequired,
  refetch: PropTypes.func.isRequired,
};
