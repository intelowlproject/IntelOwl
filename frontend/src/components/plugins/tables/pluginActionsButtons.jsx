import React from "react";
import PropTypes from "prop-types";
import {
  Button,
  Modal,
  ModalHeader,
  ModalBody,
  UncontrolledTooltip,
} from "reactstrap";
import { RiHeartPulseLine } from "react-icons/ri";
import {
  MdDelete,
  MdFileDownload,
  MdEdit,
  MdInfoOutline,
} from "react-icons/md";
import { BsPeopleFill } from "react-icons/bs";
import { AiFillSetting } from "react-icons/ai";
import { FaDiagramProject } from "react-icons/fa6";
import { VscJson } from "react-icons/vsc";
import { Link } from "react-router-dom";

import { IconButton, CustomJsonInput } from "@certego/certego-ui";

import { useAuthStore } from "../../../stores/useAuthStore";
import { useOrganizationStore } from "../../../stores/useOrganizationStore";
import { usePluginConfigurationStore } from "../../../stores/usePluginConfigurationStore";
import { SpinnerIcon } from "../../common/icon/actionIcons";
import { deleteConfiguration } from "../pluginsApi";
import { PluginsTypes } from "../../../constants/pluginConst";
import { PluginConfigModal } from "../PluginConfigModal";
import { PlaybookFlows } from "../flows/PlaybookFlows";
import {
  INTELOWL_DOCS_URL,
  INTELOWL_REPO_URL,
} from "../../../constants/environment";

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
    <div className="d-flex flex-column align-items-center p-1">
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
    isInOrganization,
    fetchAll: fetchAllOrganizations,
    isUserAdmin,
  } = useOrganizationStore(
    React.useCallback(
      (state) => ({
        fetchAll: state.fetchAll,
        isInOrganization: state.isInOrganization,
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
    <div
      className={`d-flex align-items-center ${isInOrganization ? "p-1" : ""}`}
    >
      {isInOrganization && (
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

export function PluginDeletionButton({ pluginName, pluginType_ }) {
  const [showModal, setShowModal] = React.useState(false);

  const user = useAuthStore(React.useCallback((state) => state.user, []));
  const { isInOrganization, isUserAdmin } = useOrganizationStore(
    React.useCallback(
      (state) => ({
        isInOrganization: state.isInOrganization,
        isUserAdmin: state.isUserAdmin,
      }),
      [],
    ),
  );

  const {
    retrievePlaybooksConfiguration,
    retrievePivotsConfiguration,
    retrieveAnalyzersConfiguration,
  } = usePluginConfigurationStore(
    React.useCallback(
      (state) => ({
        retrievePlaybooksConfiguration: state.retrievePlaybooksConfiguration,
        retrievePivotsConfiguration: state.retrievePivotsConfiguration,
        retrieveAnalyzersConfiguration: state.retrieveAnalyzersConfiguration,
      }),
      [],
    ),
  );

  const onClick = async () => {
    try {
      await deleteConfiguration(pluginType_, pluginName);
      if (pluginType_ === PluginsTypes.PLAYBOOK)
        retrievePlaybooksConfiguration();
      if (pluginType_ === PluginsTypes.PIVOT) retrievePivotsConfiguration();
      if (pluginType_ === PluginsTypes.ANALYZER)
        retrieveAnalyzersConfiguration();
      setShowModal(false);
    } catch {
      // handle error in deletePlugin
    }
  };

  // disabled icon for all plugins except playbooks if the user is not an admin of the org or a superuser
  const disabled =
    pluginType_ !== "playbook" &&
    ((isInOrganization && !isUserAdmin(user.username)) ||
      (!isInOrganization && !user.is_staff));

  return (
    <div className="p-1">
      <IconButton
        id={`plugin-deletion-${pluginName}`}
        color="danger"
        size="sm"
        Icon={MdDelete}
        title="Delete plugin"
        onClick={() => setShowModal(true)}
        disabled={disabled}
        titlePlacement="top"
      />
      <Modal
        id={`modal-plugin-deletion-${pluginName}`}
        autoFocus
        centered
        zIndex="1050"
        size="lg"
        backdrop="static"
        labelledBy="Plugin deletion modal"
        isOpen={showModal}
        toggle={() => setShowModal(!showModal)}
      >
        <ModalHeader className="mx-2" toggle={() => setShowModal(!showModal)}>
          <small className="text-info">Delete plugin</small>
        </ModalHeader>
        <ModalBody className="d-flex justify-content-between my-2 mx-2">
          <div>
            Do you want to delete the plugin:{" "}
            <span className="text-info">{pluginName}</span>?
          </div>
          <div className="d-flex justify-content-between">
            <Button className="mx-2" color="danger" size="sm" onClick={onClick}>
              Delete
            </Button>
            <Button
              className="mx-2"
              size="sm"
              onClick={() => setShowModal(!showModal)}
            >
              Cancel
            </Button>
          </div>
        </ModalBody>
      </Modal>
    </div>
  );
}

PluginDeletionButton.propTypes = {
  pluginName: PropTypes.string.isRequired,
  pluginType_: PropTypes.oneOf([
    "analyzer",
    "connector",
    "ingestor",
    "pivot",
    "playbook",
  ]).isRequired,
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
    <div className="d-flex flex-column align-items-center p-1">
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

export function PlaybooksEditButton({ playbookConfig }) {
  const [showModal, setShowModal] = React.useState(false);

  const [
    analyzersLoading,
    connectorsLoading,
    visualizersLoading,
    pivotsLoading,
  ] = usePluginConfigurationStore((state) => [
    state.analyzersLoading,
    state.connectorsLoading,
    state.visualizersLoading,
    state.pivotsLoading,
  ]);

  const pluginsLoading =
    analyzersLoading ||
    connectorsLoading ||
    visualizersLoading ||
    pivotsLoading;

  return (
    <div className="d-flex flex-column align-items-center p-1">
      <IconButton
        id={`playbook-edit-btn__${playbookConfig?.name}`}
        color="info"
        size="sm"
        Icon={pluginsLoading ? SpinnerIcon : MdEdit}
        title={
          pluginsLoading
            ? "Playbook configuration is loading"
            : "Edit playbook config"
        }
        onClick={() => {
          if (!pluginsLoading) setShowModal(true);
          return null;
        }}
        titlePlacement="top"
      />
      {showModal && (
        <PluginConfigModal
          pluginConfig={playbookConfig}
          pluginType={PluginsTypes.PLAYBOOK}
          toggle={setShowModal}
          isOpen={showModal}
        />
      )}
    </div>
  );
}

PlaybooksEditButton.propTypes = {
  playbookConfig: PropTypes.object.isRequired,
};

export function PluginConfigButton({ pluginConfig, pluginType_ }) {
  const [showModal, setShowModal] = React.useState(false);

  const user = useAuthStore(React.useCallback((state) => state.user, []));
  const { isInOrganization, isUserAdmin } = useOrganizationStore(
    React.useCallback(
      (state) => ({
        isInOrganization: state.isInOrganization,
        isUserAdmin: state.isUserAdmin,
      }),
      [],
    ),
  );

  const isBasicAnalyzer =
    pluginType_ === PluginsTypes.ANALYZER &&
    pluginConfig.python_module ===
      "basic_observable_analyzer.BasicObservableAnalyzer";
  let title = "Plugin config";
  if (isBasicAnalyzer) {
    title = "Edit analyzer config";
  }

  // disabled icon if the user is not an admin of the org or a superuser (only for basic analyzer)
  const disabled =
    (isInOrganization && !isUserAdmin(user.username)) ||
    (!isInOrganization && !user.is_staff);

  return (
    <div className="d-flex flex-column align-items-center p-1">
      <IconButton
        id={`plugin-config-btn__${pluginConfig?.name}`}
        color={pluginConfig.verification.configured ? "success" : "warning"}
        size="sm"
        Icon={isBasicAnalyzer ? MdEdit : AiFillSetting}
        disabled={
          (isBasicAnalyzer || pluginType_ === PluginsTypes.PIVOT) && disabled
        }
        title={
          pluginConfig.verification.configured
            ? title
            : `Plugin config: ${pluginConfig.verification.details}`
        }
        onClick={() => setShowModal(true)}
        titlePlacement="top"
      />
      {showModal && (
        <PluginConfigModal
          pluginConfig={pluginConfig}
          pluginType={pluginType_}
          toggle={setShowModal}
          isOpen={showModal}
        />
      )}
    </div>
  );
}

PluginConfigButton.propTypes = {
  pluginConfig: PropTypes.object.isRequired,
  pluginType_: PropTypes.oneOf([
    "analyzer",
    "connector",
    "ingestor",
    "pivot",
    "visualizer",
  ]).isRequired,
};

export function PlaybookFlowsButton({ playbook }) {
  // state
  const [showModal, setShowModal] = React.useState(false);

  return (
    <div className="d-flex flex-column align-items-center p-1">
      <IconButton
        id={`playbook-flows-btn__${playbook.name}`}
        color="info"
        size="sm"
        Icon={FaDiagramProject}
        title="View possible playbook execution flows"
        onClick={() => setShowModal(!showModal)}
        titlePlacement="top"
      />
      {showModal && (
        <Modal
          id="playbook-flows-modal"
          autoFocus
          centered
          zIndex="1050"
          size="lg"
          backdrop="static"
          labelledBy="Playbook flows modal"
          isOpen={showModal}
          style={{ minWidth: "90%" }}
          toggle={() => setShowModal(!showModal)}
        >
          <ModalHeader className="mx-2" toggle={() => setShowModal(!showModal)}>
            <small className="text-info">Possible playbook flows</small>
          </ModalHeader>
          <ModalBody className="mx-2">
            <small>
              Note: Pivots are plugins designed to run automatically within a
              playbook after certain conditions are triggered. Some flows of the
              tree could miss in the analysis due to this reason.
            </small>
            <div
              id={`playbookflow-${playbook.id}`}
              style={{ overflow: "scroll", border: "1px solid #2f515e" }}
              className=" mt-2 p-2 bg-body"
            >
              <PlaybookFlows playbook={playbook} />
            </div>
          </ModalBody>
        </Modal>
      )}
    </div>
  );
}

PlaybookFlowsButton.propTypes = {
  playbook: PropTypes.object.isRequired,
};

export function MappingDataModel({ data, type, pythonModule }) {
  // state
  const [showModal, setShowModal] = React.useState(false);
  const pythonModuleName = pythonModule.split(".")[0];

  return (
    <div className="d-flex flex-column align-items-center p-1">
      <IconButton
        id={`mapping-data-model__${pythonModuleName}`}
        color="info"
        size="sm"
        Icon={VscJson}
        title="View data model mapping"
        onClick={() => setShowModal(!showModal)}
        titlePlacement="top"
        disabled={Object.keys(data).length === 0}
      />
      {showModal && (
        <Modal
          id="mapping-data-model-modal"
          autoFocus
          centered
          zIndex="1050"
          size="lg"
          backdrop="static"
          labelledBy="Data model modal"
          isOpen={showModal}
          style={{ minWidth: "50%" }}
          toggle={() => setShowModal(!showModal)}
        >
          <ModalHeader className="mx-2" toggle={() => setShowModal(!showModal)}>
            <small className="text-info">
              Data model mapping
              <MdInfoOutline
                id="dataModelMapping_infoicon"
                fontSize="16"
                className="ms-2"
              />
              <UncontrolledTooltip
                trigger="hover"
                target="dataModelMapping_infoicon"
                placement="right"
                fade={false}
                autohide={false}
                innerClassName="p-2 text-start text-nowrap md-fit-content"
              >
                The main functionality of a `DataModel` is to model an
                `Analyzer` result to a set of prearranged keys, allowing users
                to easily search, evaluate and use the analyzer result.
                <br />
                For more info check the{" "}
                <Link
                  to={`${INTELOWL_DOCS_URL}IntelOwl/usage/#datamodels`}
                  target="_blank"
                >
                  official doc.
                </Link>
              </UncontrolledTooltip>
            </small>
          </ModalHeader>
          <ModalBody className="d-flex flex-column mx-2">
            <small>
              The <strong className="text-info">keys </strong>
              represent the path used to retrieve the value in the analyzer
              report and the <strong className="text-info">value</strong> the
              path of the data model.
            </small>
            <small>
              For more info check the{" "}
              <Link
                to={`${INTELOWL_REPO_URL}tree/master/api_app/analyzers_manager/${type}_analyzers/${pythonModuleName}.py`}
                target="_blank"
              >
                analyzer&apos;s source code.
              </Link>
            </small>
            <div className="my-2 d-flex justify-content-center">
              <CustomJsonInput
                id="data_model_mapping_json"
                placeholder={data}
                viewOnly
                confirmGood={false}
              />
            </div>
          </ModalBody>
        </Modal>
      )}
    </div>
  );
}

MappingDataModel.propTypes = {
  type: PropTypes.string.isRequired,
  data: PropTypes.object.isRequired,
  pythonModule: PropTypes.string.isRequired,
};
