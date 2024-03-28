import React from "react";
import PropTypes from "prop-types";
import { Button, Modal, ModalHeader, ModalBody } from "reactstrap";
import { RiHeartPulseLine } from "react-icons/ri";
import { MdDelete, MdFileDownload } from "react-icons/md";
import { BsPeopleFill } from "react-icons/bs";

import { IconButton } from "@certego/certego-ui";

import { useAuthStore } from "../../../stores/useAuthStore";
import { useOrganizationStore } from "../../../stores/useOrganizationStore";
import { usePluginConfigurationStore } from "../../../stores/usePluginConfigurationStore";
import { SpinnerIcon } from "../../common/icon/icons";

export function PluginHealthCheckButton({ pluginName, pluginType_ }) {
  const { checkPluginHealth } = usePluginConfigurationStore(
    React.useCallback(
      (state) => ({
        checkPluginHealth: state.checkPluginHealth,
      }),
      [],
    ),
  );
  const [isLoading, setIsLoading] = React.useState(false);

  const onClick = async () => {
    setIsLoading(true);
    await checkPluginHealth(pluginType_, pluginName);
    setIsLoading(false);
  };

  return (
    <div className="d-flex flex-column align-items-center px-2">
      <IconButton
        id={`table-pluginhealthcheckbtn__${pluginName}`}
        color="info"
        size="sm"
        Icon={!isLoading ? RiHeartPulseLine : SpinnerIcon}
        title={!isLoading ? "Perform health check" : "Please wait..."}
        onClick={onClick}
        titlePlacement="top"
      />
    </div>
  );
}

PluginHealthCheckButton.propTypes = {
  pluginName: PropTypes.string.isRequired,
  pluginType_: PropTypes.oneOf(["analyzer", "connector", "ingestor", "pivot"])
    .isRequired,
};

export function OrganizationPluginStateToggle({
  disabled,
  pluginName,
  type,
  refetch,
  pluginOwner,
}) {
  const user = useAuthStore(React.useCallback((state) => state.user, []));
  const {
    noOrg,
    fetchAll: fetchAllOrganizations,
    isUserAdmin,
  } = useOrganizationStore(
    React.useCallback(
      (state) => ({
        fetchAll: state.fetchAll,
        noOrg: state.noOrg,
        isUserAdmin: state.isUserAdmin,
      }),
      [],
    ),
  );
  const { enablePluginInOrg, disabledPluginInOrg } =
    usePluginConfigurationStore(
      React.useCallback(
        (state) => ({
          enablePluginInOrg: state.enablePluginInOrg,
          disabledPluginInOrg: state.disabledPluginInOrg,
        }),
        [],
      ),
    );
  let title = `${
    disabled ? "Enable" : "Disable"
  } ${pluginName} for organization`;
  if (!isUserAdmin(user.username)) {
    title = `${pluginName} is ${
      disabled ? "disabled" : "enabled"
    } for the organization`;
  }

  const onClick = async () => {
    if (disabled) enablePluginInOrg(type, pluginName, pluginOwner);
    else disabledPluginInOrg(type, pluginName, pluginOwner);
    fetchAllOrganizations();
    refetch();
  };
  return (
    <div className={`d-flex align-items-center ${noOrg ? "" : "px-2"}`}>
      {!noOrg && (
        <IconButton
          id={`table-pluginstatebtn__${pluginName}`}
          color={disabled ? "dark" : "success"}
          size="sm"
          Icon={BsPeopleFill}
          title={title}
          onClick={isUserAdmin(user.username) && onClick}
          titlePlacement="top"
        />
      )}
    </div>
  );
}

OrganizationPluginStateToggle.propTypes = {
  disabled: PropTypes.bool.isRequired,
  pluginName: PropTypes.string.isRequired,
  type: PropTypes.string.isRequired,
  refetch: PropTypes.func.isRequired,
  pluginOwner: PropTypes.string,
};

OrganizationPluginStateToggle.defaultProps = {
  pluginOwner: null,
};

export function PlaybooksDeletionButton({ playbookName }) {
  const [showModal, setShowModal] = React.useState(false);

  const { deletePlaybook, retrievePlaybooksConfiguration } =
    usePluginConfigurationStore(
      React.useCallback(
        (state) => ({
          deletePlaybook: state.deletePlaybook,
          retrievePlaybooksConfiguration: state.retrievePlaybooksConfiguration,
        }),
        [],
      ),
    );

  const onClick = async () => {
    try {
      await deletePlaybook(playbookName);
      setShowModal(false);
      await retrievePlaybooksConfiguration();
    } catch {
      // handle error in deletePlaybook
    }
  };

  return (
    <div>
      <IconButton
        id={`playbook-deletion-${playbookName}`}
        color="danger"
        size="sm"
        Icon={MdDelete}
        title="Delete playbook"
        onClick={() => setShowModal(true)}
        titlePlacement="top"
      />
      <Modal
        id={`modal-playbook-deletion-${playbookName}`}
        autoFocus
        centered
        zIndex="1050"
        size="lg"
        keyboard={false}
        backdrop="static"
        labelledBy="Playbook deletion modal"
        isOpen={showModal}
      >
        <ModalHeader className="mx-2" toggle={() => setShowModal(false)}>
          <small className="text-info">Delete playbook</small>
        </ModalHeader>
        <ModalBody className="d-flex justify-content-between my-2 mx-2">
          <div>
            Do you want to delete the playbook:{" "}
            <span className="text-info">{playbookName}</span>?
          </div>
          <div className="d-flex justify-content-between">
            <Button className="mx-2" color="danger" size="sm" onClick={onClick}>
              Delete
            </Button>
            <Button
              className="mx-2"
              size="sm"
              onClick={() => setShowModal(false)}
            >
              Cancel
            </Button>
          </div>
        </ModalBody>
      </Modal>
    </div>
  );
}

PlaybooksDeletionButton.propTypes = {
  playbookName: PropTypes.string.isRequired,
};

export function PluginPullButton({ pluginName, pluginType_ }) {
  const { pluginPull } = usePluginConfigurationStore(
    React.useCallback(
      (state) => ({
        pluginPull: state.pluginPull,
      }),
      [],
    ),
  );
  const [isLoading, setIsLoading] = React.useState(false);

  const onClick = async () => {
    setIsLoading(true);
    await pluginPull(pluginType_, pluginName);
    setIsLoading(false);
  };

  return (
    <div className="d-flex flex-column align-items-center px-2">
      <IconButton
        id={`table-pluginpullbtn__${pluginName}`}
        color="info"
        size="sm"
        Icon={!isLoading ? MdFileDownload : SpinnerIcon}
        title={!isLoading ? "Pull" : "Please wait..."}
        onClick={onClick}
        titlePlacement="top"
      />
    </div>
  );
}

PluginPullButton.propTypes = {
  pluginName: PropTypes.string.isRequired,
  pluginType_: PropTypes.oneOf(["analyzer", "connector", "ingestor", "pivot"])
    .isRequired,
};
