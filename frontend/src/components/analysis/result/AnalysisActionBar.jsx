import React from "react";
import PropTypes from "prop-types";
import { useNavigate } from "react-router-dom";

import { ContentSection, IconButton, addToast } from "@certego/certego-ui";

import { deleteAnalysis } from "./analysisApi";
import { DeleteIcon } from "../../common/icon/icons";
import { areYouSureConfirmDialog } from "../../common/areYouSureConfirmDialog";

export function AnalysisActionsBar({ analysis }) {
  // routers
  const navigate = useNavigate();

  // callbacks
  const onDeleteBtnClick = async () => {
    const sure = await areYouSureConfirmDialog(
      `delete analysis #${analysis.id}`,
    );
    if (!sure) return null;
    const success = await deleteAnalysis(analysis.id);
    if (!success) return null;
    addToast("Redirecting...", null, "secondary");
    setTimeout(() => navigate(-1), 250);
    return null;
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
