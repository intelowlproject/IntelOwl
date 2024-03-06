import React from "react";
import PropTypes from "prop-types";
import useAxios from "axios-hooks";
import { Col, Row, Container, Input } from "reactstrap";
import { MdEdit, MdRemoveRedEye } from "react-icons/md";
import { useLocation } from "react-router-dom";

import { IconButton, Loader } from "@certego/certego-ui";
import { StatusIcon } from "../../common/icon/StatusIcon";

import { AnalysisInfoCard } from "./AnalysisInfoCard";
import { AnalysisActionsBar } from "./AnalysisActionBar";
import { updateAnalysis } from "./analysisApi";
import { AnalysisFlow } from "../flow/AnalysisFlow";
import { ANALYSIS_BASE_URI } from "../../../constants/apiURLs";

export function AnalysisOverview({
  isRunningAnalysis,
  analysis,
  refetchAnalysis,
}) {
  console.debug("AnalysisOverview rendered");

  // state
  const location = useLocation();
  console.debug(
    `location pathname: ${location.pathname}, state: ${JSON.stringify(
      location?.state,
    )}`,
  );

  // API to download analysis tree
  const [{ data: analysisTree, loading, error }, refetchTree] = useAxios({
    url: `${ANALYSIS_BASE_URI}/${analysis.id}/tree`,
  });

  // refetch tree after the analysis is complete
  React.useEffect(() => {
    if (!loading) refetchTree();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isRunningAnalysis]);

  const [isEditing, setIsEditing] = React.useState(false);
  const [analysisDescription, setAnalysisDescription] = React.useState(
    analysis?.description,
  );

  // API to edit analysis description
  const editAnalysisDescription = async () => {
    if (analysis.description !== analysisDescription) {
      const success = await updateAnalysis(analysis.id, {
        description: analysisDescription,
      });
      if (!success) return;
    }
    setIsEditing(false);
  };

  return (
    <Container fluid className="mb-4">
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
          <span className="fw-bold me-2 text-light">Description</span>
          <IconButton
            id="edit-analysis-description"
            Icon={MdEdit}
            size="sm"
            color=""
            className="text-secondary"
            onClick={() => setIsEditing(true)}
            title="Edit description"
            titlePlacement="top"
          />
          {isEditing && (
            <IconButton
              id="view-analysis-description"
              Icon={MdRemoveRedEye}
              size="sm"
              color=""
              className="text-secondary"
              onClick={editAnalysisDescription}
              title="View description"
              titlePlacement="top"
            />
          )}
          {!isEditing && (
            <div
              className={`form-control bg-dark border-dark ${
                analysisDescription ? "text-light" : "text-gray"
              }`}
              style={{
                maxHeight: "200px",
                overflowY: "auto",
                whiteSpace: "pre-line",
              }}
            >
              {analysisDescription || "No description"}
            </div>
          )}
          {isEditing && (
            <Input
              id="edit_analysis-input"
              name="textArea"
              type="textarea"
              onChange={(event) => {
                setAnalysisDescription(event.target.value);
              }}
              placeholder="Enter a description"
              value={analysisDescription}
              style={{ minHeight: "200px", overflowY: "auto" }}
              className="bg-dark"
            />
          )}
        </div>
      </Row>
      <Row
        className="g-0 mt-3"
        style={{ width: "100%", height: "70%", border: "1px solid #0b2b38" }}
      >
        <Loader
          loading={loading}
          error={error}
          render={() => (
            <AnalysisFlow
              analysisTree={analysisTree}
              analysisId={analysis.id}
              refetchTree={refetchTree}
              refetchAnalysis={refetchAnalysis}
            />
          )}
        />
      </Row>
    </Container>
  );
}

AnalysisOverview.propTypes = {
  isRunningAnalysis: PropTypes.bool.isRequired,
  analysis: PropTypes.object.isRequired,
  refetchAnalysis: PropTypes.func.isRequired,
};
