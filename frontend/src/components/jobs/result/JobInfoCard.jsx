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
import { VscGlobe, VscFile } from "react-icons/vsc";

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
import { extractCountry } from "./utils/extractCountry";
import { getIcon } from "./visualizer/icons";
import { ObservableClassifications } from "../../../constants/jobConst";

export function JobInfoCard({ job }) {
  // local state
  const [isOpen, setIsOpen] = React.useState(false);
  const country = extractCountry(job);
  const countryIcon = getIcon(country.countryCode);

  return (
    <div id="JobInfoCardSection">
      <ContentSection className="mb-0 bg-darker">
        <Row>
          <Col
            className="d-flex-start-start justify-content-center offset-md-1"
            sm={12}
            md={10}
          >
            <h3>
              {job.is_sample && <VscFile className="me-1" />}
              {job?.observable_classification ===
                ObservableClassifications.IP &&
                country.countryCode && (
                  <span className="px-1">
                    {countryIcon}
                    <UncontrolledTooltip
                      placement="right"
                      target={`Icon-${country.countryCode.toLowerCase()}`}
                    >
                      {country.countryName}
                    </UncontrolledTooltip>
                  </span>
                )}
              {!job.is_sample &&
                (job?.observable_classification !==
                  ObservableClassifications.IP ||
                  (job?.observable_classification ===
                    ObservableClassifications.IP &&
                    !country.countryCode)) && <VscGlobe className="me-1" />}
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
            <Badge className="ms-1 float-end" color="info">
              {job.is_sample
                ? `file: ${job.file_mimetype}`
                : job.observable_classification}
            </Badge>
          </Col>
          <Col sm={12} md={1} className="d-flex justify-content-end">
            <Button
              className="bg-darker border-0"
              onClick={() => setIsOpen(!isOpen)}
              id="JobInfoCardDropDown"
            >
              <ArrowToggleIcon isExpanded={isOpen} />
            </Button>
            <UncontrolledTooltip placement="left" target="JobInfoCardDropDown">
              Toggle Job Metadata
            </UncontrolledTooltip>
          </Col>
        </Row>
      </ContentSection>
      <Collapse isOpen={isOpen} id="JobInfoCardCollapse">
        <ContentSection className="border-top-0 bg-body ps-0 pe-1 py-1">
          <ListGroup
            horizontal
            className="align-items-start flex-wrap flex-lg-nowrap"
          >
            {[
              ["Status", <StatusTag status={job.status} />],
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
              <ListGroupItem key={key}>
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
                job.tags.map((tag) => (
                  <JobTag key={tag.label} tag={tag} className="me-2" />
                )),
              ],
              [
                "Warning(s)",
                <ul className="text-warning">
                  {job.warnings.map((error) => (
                    <li>{error}</li>
                  ))}
                </ul>,
              ],
              [
                "Error(s)",
                <ul className="text-danger">
                  {job.errors.map((error) => (
                    <li>{error}</li>
                  ))}
                </ul>,
              ],
            ].map(([key, value]) => (
              <ListGroupItem key={key}>
                <small className="fw-bold text-light">{key}</small>
                <div className="bg-dark p-1">{value}</div>
              </ListGroupItem>
            ))}
          </ListGroup>
        </ContentSection>
      </Collapse>
    </div>
  );
}

JobInfoCard.propTypes = {
  job: PropTypes.object.isRequired,
};
