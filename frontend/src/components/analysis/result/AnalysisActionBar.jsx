import React from "react";
import PropTypes from "prop-types";
import { useNavigate } from "react-router-dom";

import { ContentSection, IconButton, addToast } from "@certego/certego-ui";

import { deleteAnalysis } from "./analysisApi";
import { DeleteIcon } from "../../common/icon/icons";

export function AnalysisActionsBar({ analysis }) {
  // routers
  const navigate = useNavigate();

  // callbacks
  const onDeleteBtnClick = async () => {
    const success = await deleteAnalysis(analysis.id);
    if (!success) return;
    addToast("Redirecting...", null, "secondary");
    setTimeout(() => navigate(-1), 250);
  };

  return (
    <ContentSection className="d-inline-flex me-2">
      <IconButton
        id="deletebtn"
        Icon={DeleteIcon}
        size="sm"
        color="darker"
        onClick={onDeleteBtnClick}
        title="Delete Analysis"
        titlePlacement="top"
      />
    </ContentSection>
  );
}

AnalysisActionsBar.propTypes = {
  analysis: PropTypes.object.isRequired,
};
