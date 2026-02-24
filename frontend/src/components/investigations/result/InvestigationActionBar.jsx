import React from "react";
import PropTypes from "prop-types";
import { useNavigate } from "react-router-dom";

import { ContentSection, IconButton, addToast } from "@certego/certego-ui";

import { deleteInvestigation } from "./investigationApi";
import { DeleteIcon } from "../../common/icon/actionIcons";
import { areYouSureConfirmDialog } from "../../common/areYouSureConfirmDialog";

export function InvestigationActionsBar({ investigation }) {
  // routers
  const navigate = useNavigate();

  // callbacks
  const onDeleteBtnClick = async () => {
    const sure = await areYouSureConfirmDialog(
      `delete investigation #${investigation.id}`,
    );
    if (!sure) return null;
    const success = await deleteInvestigation(investigation.id);
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
        title="Delete Investigation"
        titlePlacement="top"
      />
    </ContentSection>
  );
}

InvestigationActionsBar.propTypes = {
  investigation: PropTypes.object.isRequired,
};
