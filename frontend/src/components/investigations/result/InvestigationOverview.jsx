import React from "react";
import PropTypes from "prop-types";
import useAxios from "axios-hooks";
import { Col, Row, Container, Input } from "reactstrap";
import { MdEdit } from "react-icons/md";
import { BsFillCheckSquareFill, BsMarkdown } from "react-icons/bs";
import { useLocation } from "react-router-dom";

import { IconButton, Loader } from "@certego/certego-ui";
import { StatusIcon } from "../../common/icon/StatusIcon";

import { InvestigationInfoCard } from "./InvestigationInfoCard";
import { InvestigationActionsBar } from "./InvestigationActionBar";
import { updateInvestigation } from "./investigationApi";
import { InvestigationFlow } from "../flow/InvestigationFlow";
import { INVESTIGATION_BASE_URI } from "../../../constants/apiURLs";
import { markdownToHtml } from "../../common/markdownToHtml";

export function InvestigationOverview({
  isRunningInvestigation,
  investigation,
  refetchInvestigation,
}) {
  console.debug("InvestigationOverview rendered");

  // state
  const location = useLocation();
  console.debug(
    `location pathname: ${location.pathname}, state: ${JSON.stringify(
      location?.state,
    )}`,
  );

  // API to download investigation tree
  const [{ data: investigationTree, loading, error }, refetchTree] = useAxios({
    url: `${INVESTIGATION_BASE_URI}/${investigation.id}/tree`,
  });

  // refetch tree after the investigation is complete
  React.useEffect(() => {
    if (!loading) refetchTree();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isRunningInvestigation]);

  const [isEditing, setIsEditing] = React.useState(false);
  const [investigationDescription, setInvestigationDescription] =
    React.useState(investigation?.description);

  // API to edit investigation description
  const editInvestigationDescription = async () => {
    if (investigation.description !== investigationDescription) {
      const success = await updateInvestigation(investigation.id, {
        description: investigationDescription,
      });
      if (!success) return;
    }
    setIsEditing(false);
  };

  return (
    <Container fluid className="mb-4">
      {/* bar with investigation id and utilities buttons */}
      <Row
        className="g-0 d-flex-between-end align-items-center mb-2"
        id="utilitiesRow"
      >
        <Col>
          <h2 className="mb-0">
            <span className="me-2 text-secondary">
              Investigation #{investigation.id}
            </span>
            <StatusIcon status={investigation.status} className="small" />
          </h2>
        </Col>
        <Col className="d-flex justify-content-end mt-1">
          <InvestigationActionsBar investigation={investigation} />
        </Col>
      </Row>
      {/* investigation metadata card */}
      <Row className="g-0">
        <Col>
          <InvestigationInfoCard
            investigation={investigation}
            refetchTree={refetchTree}
          />
        </Col>
      </Row>
      <Row className="g-0 mt-3">
        <div className="">
          <span className="fw-bold me-2 text-light">Description</span>
          <IconButton
            id="edit-investigation-description"
            Icon={MdEdit}
            color=""
            className="text-secondary justify-content-center mx-0 px-1"
            onClick={() => setIsEditing(true)}
            title="Edit description"
            titlePlacement="top"
          />
          <IconButton
            id="investigation-markdown-doc"
            Icon={BsMarkdown}
            color=""
            className="text-secondary mx-0 px-1"
            title="Markdown syntax"
            titlePlacement="top"
            href="https://docs.github.com/en/get-started/writing-on-github/getting-started-with-writing-and-formatting-on-github/basic-writing-and-formatting-syntax"
            target="_blank"
            rel="noreferrer"
          />
          {isEditing && (
            <IconButton
              id="save-investigation-description"
              Icon={BsFillCheckSquareFill}
              color=""
              className="text-secondary mx-0 px-1"
              onClick={editInvestigationDescription}
              title="Save"
              titlePlacement="top"
            />
          )}
        </div>
      </Row>
      <Row className="g-0 mt-0 mb-2">
        {isEditing ? (
          <Input
            id="edit-investigation-description-input"
            name="textArea"
            type="textarea"
            onChange={(event) => {
              setInvestigationDescription(event.target.value);
            }}
            placeholder="Enter a description"
            value={investigationDescription}
            style={{ minHeight: "200px", overflowY: "auto" }}
            className="bg-dark"
          />
        ) : (
          <div
            className={`form-control bg-dark border-dark ${
              investigationDescription ? "text-light" : "text-gray"
            }`}
            style={{
              maxHeight: "200px",
              overflowY: "auto",
              whiteSpace: "pre-line",
              lineHeight: "0.7",
            }}
          >
            {investigationDescription
              ? markdownToHtml(investigationDescription)
              : "No description"}
          </div>
        )}
      </Row>
      <Row
        className="g-0 mt-3"
        style={{ width: "100%", height: "70%", border: "1px solid #0b2b38" }}
      >
        <Loader
          loading={loading}
          error={error}
          render={() => (
            <InvestigationFlow
              investigationTree={investigationTree}
              investigationId={investigation.id}
              refetchTree={refetchTree}
              refetchInvestigation={refetchInvestigation}
            />
          )}
        />
      </Row>
    </Container>
  );
}

InvestigationOverview.propTypes = {
  isRunningInvestigation: PropTypes.bool.isRequired,
  investigation: PropTypes.object.isRequired,
  refetchInvestigation: PropTypes.func.isRequired,
};
