import React from "react";
import PropTypes from "prop-types";
import { DropdownToggle, DropdownMenu, UncontrolledDropdown } from "reactstrap";
import { TiThMenu } from "react-icons/ti";
import { MdOutlineRefresh } from "react-icons/md";

import { IconButton, DropdownNavLink } from "@certego/certego-ui";

import { addEvaluationIcon } from "../../common/icon/actionIcons";
import { UserEventModal } from "../../userEvents/UserEventModal";

export function AnalyzableActionsBar({ analyzable }) {
  const [showUserEventModal, setShowUserEventModal] = React.useState(false);

  return (
    <div className="d-inline-flex">
      <IconButton
        id="addUserEvaluationBtn"
        Icon={addEvaluationIcon}
        size="sm"
        color="secondary"
        title="Add your evaluation"
        titlePlacement="top"
        className="me-2"
        onClick={() => setShowUserEventModal(!showUserEventModal)}
      />
      {showUserEventModal && (
        <UserEventModal
          analyzables={[analyzable]}
          toggle={setShowUserEventModal}
          isOpen={showUserEventModal}
        />
      )}
      <UncontrolledDropdown inNavbar>
        <DropdownToggle nav className="text-center">
          <IconButton
            id="artifactActions"
            Icon={TiThMenu}
            size="sm"
            color="light"
            title="Artifact actions"
            titlePlacement="top"
          />
        </DropdownToggle>
        <DropdownMenu end className="bg-dark" data-bs-popper>
          <DropdownNavLink
            to={`/scan?observable=${analyzable.name}`}
            target="_blank"
            className=" d-flex align-items-center text-light"
          >
            <MdOutlineRefresh className="text-accent me-1" />
            Rescan
          </DropdownNavLink>
        </DropdownMenu>
      </UncontrolledDropdown>
    </div>
  );
}

AnalyzableActionsBar.propTypes = {
  analyzable: PropTypes.object.isRequired,
};
