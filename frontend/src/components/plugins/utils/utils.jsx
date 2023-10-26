import React from "react";
import PropTypes from "prop-types";
import classnames from "classnames";
import {
  UncontrolledTooltip,
  Spinner,
  Card,
  CardHeader,
  CardBody,
  Badge,
  UncontrolledPopover,
  Button,
  Collapse,
  Modal,
  ModalHeader,
  ModalBody,
} from "reactstrap";
import { RiHeartPulseLine } from "react-icons/ri";
import { MdInfo, MdDelete } from "react-icons/md";
import { BsPeopleFill } from "react-icons/bs";

import { IconButton, BooleanIcon, ArrowToggleIcon } from "@certego/certego-ui";

import { markdownToHtml, TLPTag, JobTag } from "../../common";
import {
  useAuthStore,
  useOrganizationStore,
  usePluginConfigurationStore,
} from "../../../stores";
import { pluginsTypes, scanMode } from "../../../constants/constants";

export function parseScanCheckTime(time) {
  // scan_check_time is in format days:hours:minutes:seconds, we need to convert them to hours
  const [daysAgo, hoursAgo] = time
    .split(":")
    .map((token) => parseInt(token, 10));
  return daysAgo * 24 + hoursAgo;
}

export function PluginInfoCard({ pluginInfo }) {
  console.debug(pluginInfo);
  return (
    <Card className="flat border-dark h-100 w-100">
      <CardHeader className="d-flex align-items-center bg-body p-2 h5">
        <span>{pluginInfo?.name}</span>
        {pluginInfo.python_module && (
          <code className="ml-1 font-italic small">
            ( {pluginInfo?.python_module} )
          </code>
        )}
        {pluginInfo?.maximum_tlp && (
          <TLPTag className="ms-auto me-0" value={pluginInfo.maximum_tlp} />
        )}
      </CardHeader>
      <CardBody className="bg-darker border-top border-tertiary">
        <div>
          <h6 className="text-secondary">Description</h6>
          <p>{markdownToHtml(pluginInfo?.description)}</p>
        </div>
        <div>
          <div>
            {pluginInfo.config && (
              <h6 className="text-secondary">Configuration</h6>
            )}
            <ul>
              {pluginInfo.config &&
                Object.entries(pluginInfo?.config).map(([key, value]) => (
                  <li
                    key={`plugininfocard-configuration__${pluginInfo?.name}-${key}`}
                  >
                    <span>{key}: </span>
                    <code>{JSON.stringify(value, null, 2)}</code>
                  </li>
                ))}
            </ul>
          </div>
          <div>
            {pluginInfo?.params && (
              <h6 className="text-secondary">Parameters</h6>
            )}
            <ul>
              {pluginInfo?.params &&
                Object.entries(pluginInfo?.params).map(([key, value]) => (
                  <li key={`plugininfocard-params__${pluginInfo?.name}-${key}`}>
                    <span>{key}: </span>
                    <code>{JSON.stringify(value.value, null, 2)}</code>
                    &nbsp;
                    <em className="text-muted">({value.type})</em>
                    <dd className="text-muted">
                      {markdownToHtml(value.description)}
                    </dd>
                  </li>
                ))}
            </ul>
          </div>
          {pluginInfo?.secrets && <h6 className="text-secondary">Secrets</h6>}
          <ul>
            {pluginInfo.secrets &&
              Object.entries(pluginInfo?.secrets).map(([key, value]) => (
                <li key={`plugininfocard-secrets__${pluginInfo?.name}-${key}`}>
                  <span>
                    {key}
                    &nbsp; (<code className="small">{value.env_var_key}</code>)
                    &nbsp;
                    {value.required && (
                      <Badge
                        size="sm"
                        color="info"
                        className="user-select-none"
                      >
                        required
                      </Badge>
                    )}
                  </span>
                  <dd className="text-muted">
                    {markdownToHtml(value.description)}
                  </dd>
                </li>
              ))}
          </ul>
          {pluginInfo?.verification && (
            <div>
              <h6 className="text-secondary">
                Verification &nbsp;
                <PluginVerificationIcon
                  pluginName={pluginInfo.name}
                  verification={pluginInfo.verification}
                />
              </h6>
              <p className="small text-danger">
                {!pluginInfo?.verification.configured &&
                  pluginInfo?.verification.details}
              </p>
            </div>
          )}
        </div>
        {pluginInfo?.analyzers != null && (
          <div>
            <h6 className="text-secondary">Analyzers &nbsp;</h6>
            <ul>
              {Object.entries(pluginInfo?.analyzers).map(([key, value]) => (
                <li key={`plugininfocard-analyzer__${pluginInfo.name}-${key}`}>
                  <span>{key}</span>
                  {Object.keys(pluginInfo?.analyzers[key]).length !== 0 && (
                    <ul>
                      <b>Parameters:</b>
                      <li style={{ listStyleType: "square" }}>
                        <code>{JSON.stringify(value, null, 2)}</code>
                      </li>
                    </ul>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}
        {pluginInfo?.connectors != null && (
          <div>
            <h6 className="text-secondary">Connectors &nbsp;</h6>
            <ul>
              {Object.entries(pluginInfo?.connectors).map(([key, value]) => (
                <li
                  key={`plugininfocard-connector__${pluginInfo?.name}-${key}`}
                >
                  <span>{key}</span>
                  {Object.keys(pluginInfo?.connectors[key]).length !== 0 && (
                    <ul>
                      <li>
                        <code>{JSON.stringify(value, null, 2)}</code>
                      </li>
                    </ul>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}
        {pluginInfo?.plugin_type === pluginsTypes.PLAYBOOK && (
          <div>
            <h6 className="text-secondary">Advanced Settings &nbsp;</h6>
            <ul>
              {pluginInfo?.tlp && (
                <li>
                  <strong>TLP:</strong>{" "}
                  <TLPTag className="ms-auto me-0" value={pluginInfo.tlp} />
                </li>
              )}
              {pluginInfo?.scan_mode && (
                <li>
                  <strong>Scan mode:</strong>{" "}
                  {pluginInfo.scan_mode === scanMode[0]
                    ? "force new analysis"
                    : `a new scan is not performed if there is a similar one finished in the last 
                ${parseScanCheckTime(pluginInfo?.scan_check_time)} hours`}
                </li>
              )}
              {pluginInfo?.tags.length > 0 && (
                <li>
                  {" "}
                  <strong>Tags:</strong>
                  {pluginInfo.tags.map((tag) => (
                    <JobTag
                      key={`jobtable-tags-${tag.label}`}
                      tag={tag}
                      className="ms-2"
                    />
                  ))}
                </li>
              )}
            </ul>
          </div>
        )}
      </CardBody>
    </Card>
  );
}

export function PluginInfoPopoverIcon({ pluginInfo }) {
  const noSpaceName = pluginInfo.name.replaceAll(" ", "_");
  return (
    <div>
      <MdInfo
        id={`table-infoicon__${noSpaceName}`}
        className="text-info"
        fontSize="20"
      />
      <UncontrolledPopover
        trigger="hover"
        delay={{ show: 0, hide: 500 }}
        target={`table-infoicon__${noSpaceName}`}
        popperClassName="p-0 w-33"
      >
        <PluginInfoCard pluginInfo={pluginInfo} />
      </UncontrolledPopover>
    </div>
  );
}

export function PluginVerificationIcon({ pluginName, verification }) {
  const divId = `table-pluginverificationicon__${pluginName}`;
  return (
    <span id={divId}>
      <BooleanIcon withColors truthy={verification.configured} />
      <UncontrolledTooltip
        target={divId}
        placement="top"
        fade={false}
        innerClassName={classnames(
          "text-start text-nowrap md-fit-content border border-darker",
          {
            "bg-success text-darker": verification.configured,
            "bg-danger text-darker": !verification.configured,
          },
        )}
      >
        {verification.details}
      </UncontrolledTooltip>
    </span>
  );
}

function PluginHealthSpinner() {
  return <Spinner type="ripple" size="sm" className="text-darker" />;
}

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
  const [isHealthy, setIsHealthy] = React.useState(undefined);

  const onClick = async () => {
    setIsLoading(true);
    const status = await checkPluginHealth(pluginType_, pluginName);
    setIsHealthy(status);
    setIsLoading(false);
  };

  return (
    <div className="d-flex flex-column align-items-center">
      <IconButton
        id={`table-pluginhealthcheckbtn__${pluginName}`}
        color="info"
        size="sm"
        Icon={!isLoading ? RiHeartPulseLine : PluginHealthSpinner}
        title={!isLoading ? "perform health check" : "please wait..."}
        onClick={onClick}
        titlePlacement="top"
      />
      {isHealthy !== undefined &&
        (isHealthy ? (
          <span className="mt-2 text-success">Up and running!</span>
        ) : (
          <span className="mt-2 text-warning">Failing!</span>
        ))}
    </div>
  );
}

export function OrganizationPluginStateToggle({
  disabled,
  pluginName,
  type,
  refetch,
  pluginOwner,
}) {
  const user = useAuthStore(React.useCallback((s) => s.user, []));
  const {
    isUserOwner,
    noOrg,
    fetchAll: fetchAllOrganizations,
    isUserAdmin,
  } = useOrganizationStore(
    React.useCallback(
      (state) => ({
        isUserOwner: state.isUserOwner,
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
  if (!isUserOwner && !isUserAdmin(user.username)) {
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
          onClick={(isUserOwner || isUserAdmin(user.username)) && onClick}
          titlePlacement="top"
        />
      )}
    </div>
  );
}

export function PlaybooksCollapse({ value, pluginType_ }) {
  // local state
  const [isOpen, setIsOpen] = React.useState(false);
  return (
    <div>
      <Button
        className="bg-transparent border-0"
        onClick={() => setIsOpen(!isOpen)}
        id="PlaybooksCollapse"
      >
        <small>
          {value?.length} {pluginType_}{" "}
        </small>
        <ArrowToggleIcon isExpanded={isOpen} />
      </Button>
      <Collapse isOpen={isOpen} id="PlaybooksCollapse">
        <ul className="d-flex flex-column align-items-start">
          {value?.sort().map((v) => (
            <li key={v}>{v}</li>
          ))}
        </ul>
      </Collapse>
    </div>
  );
}

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

PluginInfoCard.propTypes = {
  pluginInfo: PropTypes.object.isRequired,
};

PluginInfoPopoverIcon.propTypes = {
  pluginInfo: PropTypes.object.isRequired,
};

PluginVerificationIcon.propTypes = {
  pluginName: PropTypes.string.isRequired,
  verification: PropTypes.object.isRequired,
};

PluginHealthCheckButton.propTypes = {
  pluginName: PropTypes.string.isRequired,
  pluginType_: PropTypes.oneOf(["analyzer", "connector"]).isRequired,
};

PlaybooksCollapse.propTypes = {
  value: PropTypes.array.isRequired,
  pluginType_: PropTypes.oneOf(Object.values(pluginsTypes)).isRequired,
};

PlaybooksDeletionButton.propTypes = {
  playbookName: PropTypes.string.isRequired,
};
