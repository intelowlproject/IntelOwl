import React from "react";
import PropTypes from "prop-types";
import {
  Button,
  ListGroup,
  ListGroupItem,
  Collapse,
  Row,
  Col,
  UncontrolledTooltip,
} from "reactstrap";
import { MdEdit } from "react-icons/md";

import {
  ContentSection,
  DateHoverable,
  ArrowToggleIcon,
  IconButton,
} from "@certego/certego-ui";

import { JobTag } from "../../common/JobTag";
import { StatusTag } from "../../common/StatusTag";
import { TLPTag } from "../../common/TLPTag";

export function AnalysisInfoCard({ analysis }) {
  // local state
  const [isOpen, setIsOpen] = React.useState(false);

  return (
    <div id="AnalysisInfoCardSection">
      <ContentSection className="mb-0 bg-darker">
        <Row>
          <Col
            className="d-flex-start-start justify-content-center offset-md-1"
            sm={12}
            md={10}
          >
            <h3>{analysis.name}</h3>
            <IconButton
              id="edit-analysis-name"
              Icon={MdEdit}
              color=""
              className="me-2 text-secondary"
              onClick={() => null}
              title="Edit name"
              titlePlacement="top"
            />
          </Col>
          <Col sm={12} md={1} className="d-flex justify-content-end">
            <Button
              className="bg-darker border-0"
              onClick={() => setIsOpen(!isOpen)}
              id="AnalysisInfoCardDropDown"
            >
              <ArrowToggleIcon isExpanded={isOpen} />
            </Button>
            <UncontrolledTooltip
              placement="left"
              target="AnalysisInfoCardDropDown"
            >
              Toggle Analysis Metadata
            </UncontrolledTooltip>
          </Col>
        </Row>
      </ContentSection>
      <Collapse isOpen={isOpen} id="AnalysisInfoCardCollapse">
        <ContentSection className="border-top-0 bg-body ps-0 pe-1 py-1">
          <ListGroup
            horizontal
            className="align-items-start flex-wrap flex-lg-nowrap"
          >
            {[
              ["Status", <StatusTag status={analysis.status} />],
              ["TLP", <TLPTag value={analysis.tlp} />],
              [
                "Tags",
                analysis.tags.map(
                  (tag) =>
                    tag !== null && (
                      <JobTag key={tag.label} tag={tag} className="me-2" />
                    ),
                ),
              ],
              ["User", analysis.owner],
              [
                "Start Time",
                <DateHoverable
                  id={`overview-start_time__${analysis.id}`}
                  value={analysis.start_time}
                  format="hh:mm:ss a MMM do, yyyy"
                />,
              ],
            ].map(([key, value]) => (
              <ListGroupItem key={key}>
                <small className="fw-bold text-light">{key}</small>
                <div className="bg-dark p-1 text-light">{value}</div>
              </ListGroupItem>
            ))}
          </ListGroup>
        </ContentSection>
      </Collapse>
    </div>
  );
}

AnalysisInfoCard.propTypes = {
  analysis: PropTypes.object.isRequired,
};
