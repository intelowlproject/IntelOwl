import React from "react";
import PropTypes from "prop-types";
import { useNavigate } from "react-router-dom";
import {
  DropdownToggle,
  DropdownMenu,
  DropdownItem,
  UncontrolledDropdown,
} from "reactstrap";
import { TiThMenu } from "react-icons/ti";
import { MdDelete } from "react-icons/md";

import { IconButton, addToast } from "@certego/certego-ui";

import { deleteInvestigation } from "./investigationApi";
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
    <div className="d-inline-flex">
      <UncontrolledDropdown inNavbar>
        <DropdownToggle nav className="text-center">
          <IconButton
            id="investigationActions"
            Icon={TiThMenu}
            size="sm"
            color="light"
            title="Investigation actions"
            titlePlacement="top"
          />
        </DropdownToggle>
        <DropdownMenu end className="bg-dark" data-bs-popper>
          <DropdownItem
            onClick={onDeleteBtnClick}
            className=" d-flex align-items-center text-light"
          >
            <MdDelete className="text-danger me-1" />
            Delete investigation
          </DropdownItem>
        </DropdownMenu>
      </UncontrolledDropdown>
    </div>
  );
}

InvestigationActionsBar.propTypes = {
  investigation: PropTypes.object.isRequired,
};
