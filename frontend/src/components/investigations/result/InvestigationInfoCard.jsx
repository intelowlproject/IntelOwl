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
import { MdEdit } from "react-icons/md";
import { BsFillCheckSquareFill } from "react-icons/bs";

import {
  ContentSection,
  DateHoverable,
  ArrowToggleIcon,
  IconButton,
} from "@certego/certego-ui";

import { JobTag } from "../../common/JobTag";
import { StatusTag } from "../../common/StatusTag";
import { TLPTag } from "../../common/TLPTag";
import { updateInvestigation } from "./investigationApi";

export function InvestigationInfoCard({ investigation, refetchTree }) {
  // local state
  const [isOpen, setIsOpen] = React.useState(false);

  const [isEditing, setIsEditing] = React.useState(false);
  const [investigationName, setInvestigationName] = React.useState(
    investigation?.name,
  );

  const editInvestigationName = async () => {
    if (investigation.name !== investigationName) {
      const success = await updateInvestigation(investigation.id, {
        name: investigationName,
      });
      if (success) refetchTree();
      if (!success) return;
    }
    setIsEditing(false);
  };

  return (
    <div id="InvestigationInfoCardSection">
      <ContentSection className="mb-0 bg-darker">
        <Row>
          <Col
            className="d-flex-start-start justify-content-center offset-md-1"
            sm={12}
            md={10}
          >
            {isEditing ? (
              <>
                <Input
                  id="edit-investigation-name-input"
                  name="textArea"
                  type="textarea"
                  onChange={(event) => {
                    setInvestigationName(event.target.value);
                  }}
                  value={investigationName}
                  style={{
                    maxWidth: "600px",
                    maxHeight: "20px",
                    overflowX: "scroll",
                  }}
                  className="me-2 bg-dark"
                />
                <IconButton
                  id="save-investigation-name"
                  Icon={BsFillCheckSquareFill}
                  color=""
                  className="text-secondary px-1"
                  onClick={editInvestigationName}
                />
              </>
            ) : (
              <>
                <h3 className="">{investigationName}</h3>
                <IconButton
                  id="edit-investigation-name"
                  Icon={MdEdit}
                  color=""
                  className="text-secondary"
                  onClick={() => setIsEditing(true)}
                  title="Edit name"
                  titlePlacement="top"
                />
              </>
            )}
          </Col>
          <Col sm={12} md={1} className="d-flex justify-content-end">
            <Button
              className="bg-darker border-0"
              onClick={() => setIsOpen(!isOpen)}
              id="InvestigationInfoCardDropDown"
            >
              <ArrowToggleIcon isExpanded={isOpen} />
            </Button>
            <UncontrolledTooltip
              placement="left"
              target="InvestigationInfoCardDropDown"
            >
              Toggle Investigation Metadata
            </UncontrolledTooltip>
          </Col>
        </Row>
      </ContentSection>
      <Collapse isOpen={isOpen} id="InvestigationInfoCardCollapse">
        <ContentSection className="border-top-0 bg-body ps-0 pe-1 py-1">
          <ListGroup
            horizontal
            className="align-items-start flex-wrap flex-lg-nowrap"
          >
            {[
              ["Status", <StatusTag status={investigation.status} />],
              ["TLP", <TLPTag value={investigation.tlp} />],
              [
                "Tags",
                investigation.tags.map(
                  (tag) =>
                    tag !== null && (
                      <JobTag key={tag.label} tag={tag} className="me-2" />
                    ),
                ),
              ],
              ["User", investigation.owner],
              [
                "Start Time",
                <DateHoverable
                  id={`overview-start_time__${investigation.id}`}
                  value={investigation.start_time}
                  format="hh:mm:ss a MMM do, yyyy"
                />,
              ],
            ].map(([jobFieldName, jobFieldValue]) => (
              <ListGroupItem key={jobFieldName}>
                <small className="fw-bold text-light">{jobFieldName}</small>
                <div className="bg-dark p-1 text-light">{jobFieldValue}</div>
              </ListGroupItem>
            ))}
          </ListGroup>
        </ContentSection>
      </Collapse>
    </div>
  );
}

InvestigationInfoCard.propTypes = {
  investigation: PropTypes.object.isRequired,
  refetchTree: PropTypes.func.isRequired,
};
