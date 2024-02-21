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
  Input,
} from "reactstrap";
import { MdEdit, MdRemoveRedEye } from "react-icons/md";

import {
  ContentSection,
  DateHoverable,
  ArrowToggleIcon,
  IconButton,
} from "@certego/certego-ui";

import { JobTag } from "../../common/JobTag";
import { StatusTag } from "../../common/StatusTag";
import { TLPTag } from "../../common/TLPTag";
import { updateAnalysis } from "./analysisApi";

export function AnalysisInfoCard({ analysis }) {
  // local state
  const [isOpen, setIsOpen] = React.useState(false);

  const [isEditing, setIsEditing] = React.useState(false);
  const [analysisName, setAnalysisName] = React.useState(analysis?.name);

  const editAnalysisName = async () => {
    if (analysis.name !== analysisName) {
      const success = await updateAnalysis(analysis.id, { name: analysisName });
      if (!success) return;
    }
    setIsEditing(false);
  };

  return (
    <div id="AnalysisInfoCardSection">
      <ContentSection className="mb-0 bg-darker">
        <Row>
          <Col
            className="d-flex-start-start justify-content-center offset-md-1"
            sm={12}
            md={10}
          >
            {!isEditing && <h3 className="">{analysisName}</h3>}
            {isEditing && (
              <Input
                id="edit_analysis-input"
                name="textArea"
                type="textarea"
                onChange={(event) => {
                  setAnalysisName(event.target.value);
                }}
                value={analysisName}
                style={{
                  maxWidth: "600px",
                  maxHeight: "20px",
                  overflowX: "scroll",
                }}
                className="me-2 bg-dark"
              />
            )}
            <IconButton
              id="edit-analysis-name"
              Icon={MdEdit}
              color=""
              className="text-secondary"
              onClick={() => setIsEditing(true)}
              title="Edit name"
              titlePlacement="top"
            />
            {isEditing && (
              <IconButton
                id="view-analysis-name"
                Icon={MdRemoveRedEye}
                color=""
                className="text-secondary px-1"
                onClick={editAnalysisName}
                title="View name"
                titlePlacement="top"
              />
            )}
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
