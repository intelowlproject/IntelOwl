import axios from "axios";
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
} from "reactstrap";
import { RiHeartPulseLine } from "react-icons/ri";
import {
  MdInfo,
  MdOutlineCheckCircleOutline,
  MdOutlineHideSource,
} from "react-icons/md";

import { IconButton, BooleanIcon } from "@certego/certego-ui";
import { ORG_PLUGIN_DISABLE_URI } from "../../../constants/api";

import { markdownToHtml, TLPTag } from "../../common";
import {
  useOrganizationStore,
  usePluginConfigurationStore,
} from "../../../stores";

const { checkPluginHealth } = usePluginConfigurationStore.getState();

export function PluginInfoCard({ pluginInfo }) {
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
              {pluginInfo.verification?.details && (
                <div className="text-danger">
                  {pluginInfo.verification.details}
                </div>
              )}
            </div>
          )}
        </div>
        {pluginInfo?.analyzers != null && (
          <div>
            <h6 className="text-secondary">Analyzers &nbsp;</h6>
            <ul>
              {Object.entries(pluginInfo?.analyzers).map(([key, value]) => (
                <li key={`plugininfocard-analyzer__${pluginInfo?.name}-${key}`}>
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
      </CardBody>
    </Card>
  );
}

export function PluginInfoPopoverIcon({ pluginInfo }) {
  return (
    <div>
      <MdInfo
        id={`table-infoicon__${pluginInfo.name}`}
        className="text-info"
        fontSize="20"
      />
      <UncontrolledPopover
        trigger="hover"
        delay={{ show: 0, hide: 500 }}
        target={`table-infoicon__${pluginInfo.name}`}
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
          }
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

export function PluginHealthCheckButton({ pluginName, pluginType }) {
  const [isLoading, setIsLoading] = React.useState(false);
  const [isHealthy, setIsHealthy] = React.useState(undefined);

  const onClick = async () => {
    setIsLoading(true);
    const status = await checkPluginHealth(pluginType, pluginName);
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
}) {
  const {
    isUserOwner,
    organization,
    fetchAll: fetchAllOrganizations,
  } = useOrganizationStore(
    React.useCallback(
      (state) => ({
        fetchAll: state.fetchAll,
        isUserOwner: state.isUserOwner,
        organization: state.organization,
      }),
      []
    )
  );
  let title = disabled ? "Enable" : "Disable";
  if (!organization.name) title = "You're not a part of any organization";
  else if (!isUserOwner)
    title = `You're not an owner of your organization - ${organization.name}`;

  const onClick = async () => {
    if (disabled)
      await axios.delete(`${ORG_PLUGIN_DISABLE_URI}/${type}/${pluginName}/`);
    else await axios.post(`${ORG_PLUGIN_DISABLE_URI}/${type}/${pluginName}/`);
    fetchAllOrganizations();
    refetch();
  };
  return (
    <div className="d-flex flex-column align-items-center">
      <IconButton
        id={`table-pluginstatebtn__${pluginName}`}
        color={disabled ? "danger" : "info"}
        size="sm"
        Icon={disabled ? MdOutlineHideSource : MdOutlineCheckCircleOutline}
        title={title}
        onClick={onClick}
        titlePlacement="top"
      />
    </div>
  );
}

OrganizationPluginStateToggle.propTypes = {
  disabled: PropTypes.bool.isRequired,
  pluginName: PropTypes.string.isRequired,
  type: PropTypes.string.isRequired,
  refetch: PropTypes.func.isRequired,
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
  pluginType: PropTypes.oneOf(["analyzer", "connector"]).isRequired,
};
