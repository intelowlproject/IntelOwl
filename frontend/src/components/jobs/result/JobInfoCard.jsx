import React from "react";
import PropTypes from "prop-types";
import {
  Button,
  ListGroup,
  ListGroupItem,
  Badge,
  Collapse,
  Row,
  Col,
  UncontrolledTooltip,
} from "reactstrap";

import {
  ContentSection,
  DateHoverable,
  CopyToClipboardButton,
  ArrowToggleIcon,
} from "@certego/certego-ui";
import { processTimeMMSS } from "../../../utils/time";

import { JobTag } from "../../common/JobTag";
import { PlaybookTag } from "../../common/PlaybookTag";
import { StatusTag } from "../../common/StatusTag";
import { TLPTag } from "../../common/TLPTag";
import { JobInfoIcon } from "./JobInfoIcon";
import { JobIsRunningAlert } from "./JobIsRunningAlert";
import { JobFinalStatuses } from "../../../constants/jobConst";

export function JobInfoCard({ job }) {
  // local state
  const [isOpenJobInfoCard, setIsOpenJobInfoCard] = React.useState(false);
  const [isOpenJobWarnings, setIsOpenJobWarnings] = React.useState(false);
  const [isOpenJobErrors, setIsOpenJobErrors] = React.useState(false);

  const investigationTimeRange = 30;
  const endDateRelatedInvestigation = new Date();
  const startDateRelatedInvestigation = structuredClone(
    endDateRelatedInvestigation,
  );
  startDateRelatedInvestigation.setDate(
    startDateRelatedInvestigation.getDate() - investigationTimeRange,
  );

  return (
    <div id="JobInfoCardSection">
      <ContentSection className="mb-0 bg-darker">
        <Row>
          <Col
            className="d-flex-start-start justify-content-center align-items-center offset-1"
            sm={12}
            md={10}
          >
            <h3 className="d-flex-start text-truncate">
              <JobInfoIcon job={job} />
              {job.is_sample ? (
                <CopyToClipboardButton
                  showOnHover
                  id="file_name"
                  text={job.file_name}
                >
                  {job.file_name}
                </CopyToClipboardButton>
              ) : (
                <CopyToClipboardButton
                  showOnHover
                  id="observable_name"
                  text={job.observable_name}
                >
                  {job.observable_name}
                </CopyToClipboardButton>
              )}
            </h3>
            <div className="h-100 d-flex align-items-start">
              <Badge className="ms-1 float-end" color="info">
                {job.is_sample
                  ? `file: ${job.file_mimetype}`
                  : job.observable_classification}
              </Badge>
            </div>
          </Col>
          <Col sm={12} md={1} className="d-flex justify-content-end">
            <Button
              className="bg-darker border-0"
              onClick={() => setIsOpenJobInfoCard(!isOpenJobInfoCard)}
              id="JobInfoCardDropDown"
            >
              <ArrowToggleIcon isExpanded={isOpenJobInfoCard} />
            </Button>
            <UncontrolledTooltip placement="left" target="JobInfoCardDropDown">
              Toggle Job Metadata
            </UncontrolledTooltip>
          </Col>
        </Row>
      </ContentSection>
      <Collapse isOpen={isOpenJobInfoCard} id="JobInfoCardCollapse">
        <ContentSection className="border-top-0 bg-body ps-0 pe-1 py-1">
          <ListGroup
            horizontal
            className="align-items-start flex-wrap flex-lg-nowrap"
          >
            {[
              ["Status", <StatusTag status={job.status} className="py-0" />],
              ["TLP", <TLPTag value={job.tlp} />],
              ["User", job.user?.username],
              ["MD5", job.md5],
              ["Process Time (mm:ss)", processTimeMMSS(job.process_time)],
              [
                "Start Time",
                <DateHoverable
                  id={`overview-received_request_time__${job.id}`}
                  value={job.received_request_time}
                  format="hh:mm:ss a MMM do, yyyy"
                />,
              ],
              [
                "End Time",
                job.finished_analysis_time ? (
                  <DateHoverable
                    id={`overview-finished_analysis_time__${job.id}`}
                    value={job.finished_analysis_time}
                    format="hh:mm:ss a MMM do, yyyy"
                  />
                ) : (
                  "-"
                ),
              ],
            ].map(([key, value]) => (
              <ListGroupItem className="mx-2" key={key}>
                <small className="fw-bold text-light">{key}</small>
                <div className="bg-dark p-1 text-light">{value}</div>
              </ListGroupItem>
            ))}
          </ListGroup>
          <ListGroup
            horizontal
            className="align-items-start flex-wrap flex-lg-nowrap"
          >
            {[
              [
                "Playbook",
                <PlaybookTag
                  key={job.playbook_to_execute}
                  playbook={job.playbook_to_execute}
                  className="mr-2"
                />,
              ],
              [
                "Tags",
                job.tags.length ? (
                  job.tags.map((tag) => (
                    <JobTag key={tag.label} tag={tag} className="me-2" />
                  ))
                ) : (
                  <small className="fst-italic text-gray">None</small>
                ),
              ],
              [
                "Warning(s)",
                <>
                  <div className="d-flex text-warning align-items-center justify-content-between mx-2">
                    {job.warnings.length} warnings
                    <Button
                      className="bg-dark border-0 p-0"
                      onClick={() => setIsOpenJobWarnings(!isOpenJobWarnings)}
                      id="JobWarningsDropDown"
                    >
                      <ArrowToggleIcon isExpanded={isOpenJobWarnings} />
                    </Button>
                    <UncontrolledTooltip
                      placement="left"
                      target="JobWarningsDropDown"
                    >
                      Toggle Job Warnings
                    </UncontrolledTooltip>
                  </div>
                  <Collapse isOpen={isOpenJobWarnings} id="JobWarningsCollapse">
                    <ul className="text-warning">
                      {job.warnings.map((error) => (
                        <li>{error}</li>
                      ))}
                    </ul>
                  </Collapse>
                </>,
              ],
              [
                "Error(s)",
                <>
                  <div className="d-flex text-danger align-items-center justify-content-between mx-2">
                    {job.errors.length} errors
                    <Button
                      className="bg-dark border-0 p-0"
                      onClick={() => setIsOpenJobErrors(!isOpenJobErrors)}
                      id="JobErrorsDropDown"
                    >
                      <ArrowToggleIcon isExpanded={isOpenJobErrors} />
                    </Button>
                    <UncontrolledTooltip
                      placement="left"
                      target="JobErrorsDropDown"
                    >
                      Toggle Job Errors
                    </UncontrolledTooltip>
                  </div>
                  <Collapse isOpen={isOpenJobErrors} id="JobErrorsCollapse">
                    <ul className="text-danger">
                      {job.errors.map((error) => (
                        <li>{error}</li>
                      ))}
                    </ul>
                  </Collapse>
                </>,
              ],
            ].map(([key, value]) => (
              <ListGroupItem className="mx-2" key={key}>
                <small className="fw-bold text-light">{key}</small>
                <div className="bg-dark p-1">{value}</div>
              </ListGroupItem>
            ))}
          </ListGroup>
          {Object.values(JobFinalStatuses).includes(job.status) && (
            <div
              className="my-4 d-flex justify-content-center"
              style={{ width: "100%" }}
            >
              <JobIsRunningAlert job={job} />
            </div>
          )}
        </ContentSection>
      </Collapse>
    </div>
  );
}

JobInfoCard.propTypes = {
  job: PropTypes.object.isRequired,
};
