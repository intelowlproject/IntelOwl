import React from "react";
import PropTypes from "prop-types";
import classnames from "classnames";
import {
  UncontrolledTooltip,
  Card,
  CardHeader,
  CardBody,
  Badge,
  UncontrolledPopover,
  Button,
  Collapse,
} from "reactstrap";
import { MdInfo } from "react-icons/md";
import {
  BooleanIcon,
  ArrowToggleIcon,
  CopyToClipboardButton,
} from "@certego/certego-ui";
import { markdownToHtml } from "../../common/markdownToHtml";
import { JobTag } from "../../common/JobTag";
import { TLPTag } from "../../common/TLPTag";
import { JobTypes } from "../../../constants/jobConst";
import { PluginsTypes } from "../../../constants/pluginConst";
import { ScanModesNumeric } from "../../../constants/advancedSettingsConst";
import { parseScanCheckTime } from "../../../utils/time";

export function PluginInfoCard({ pluginInfo }) {
  console.debug(`pluginInfo: ${JSON.stringify(pluginInfo)}`);

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
          <span>{markdownToHtml(pluginInfo?.description)}</span>
        </div>
        <div>
          <div>
            {pluginInfo.type === JobTypes.OBSERVABLE && (
              <h6 className="text-secondary">Supported types</h6>
            )}
            <ul>
              {pluginInfo?.observable_supported?.sort().map((value) => (
                <li
                  key={`plugininfocard-supported_types__${pluginInfo?.name}-${value}`}
                >
                  {value}
                </li>
              ))}
            </ul>
          </div>
          <div>
            {pluginInfo.type === JobTypes.FILE && (
              <h6 className="text-secondary">Supported types</h6>
            )}
            <ul>
              {pluginInfo?.supported_filetypes?.sort().map((value) => (
                <li
                  key={`plugininfocard-supported_types__${pluginInfo?.name}-${value}`}
                >
                  {value}
                </li>
              ))}
            </ul>
            {pluginInfo.supported_filetypes?.[0] === "everything" &&
              pluginInfo.not_supported_filetypes.length !== 0 && (
                <div className="d-flex flex-column align-items-start">
                  <strong>Except:</strong>
                  <ul className="d-flex flex-column align-items-start">
                    {pluginInfo.not_supported_filetypes
                      ?.sort()
                      .map((unsupportFiletype) => (
                        <li key={unsupportFiletype}>{unsupportFiletype}</li>
                      ))}
                  </ul>
                </div>
              )}
          </div>
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
        {pluginInfo?.plugin_type === PluginsTypes.PLAYBOOK &&
          pluginInfo?.analyzers.length !== 0 && (
            <PlaybookPluginList
              pluginInfo={pluginInfo}
              pluginType_={PluginsTypes.ANALYZER}
            />
          )}
        {pluginInfo?.plugin_type === PluginsTypes.PLAYBOOK &&
          pluginInfo?.connectors.length !== 0 && (
            <PlaybookPluginList
              pluginInfo={pluginInfo}
              pluginType_={PluginsTypes.CONNECTOR}
            />
          )}
        {pluginInfo?.plugin_type === PluginsTypes.PLAYBOOK && (
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
                  {pluginInfo.scan_mode.toString() ===
                  ScanModesNumeric.FORCE_NEW_ANALYSIS
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

export function PlaybooksCollapse({ pluginList, pluginType_ }) {
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
          {pluginList?.length} {pluginType_}{" "}
        </small>
        <ArrowToggleIcon isExpanded={isOpen} />
      </Button>
      <Collapse isOpen={isOpen} id="PlaybooksCollapse">
        <ul className="d-flex flex-column align-items-start p-3">
          {pluginList?.sort().map((pluginName) => (
            <li className="pb-2" key={pluginName}>
              <CopyToClipboardButton
                showOnHover
                text={pluginName}
                className="d-block text-break"
              >
                {pluginName}
              </CopyToClipboardButton>
            </li>
          ))}
        </ul>
      </Collapse>
    </div>
  );
}

function PlaybookPluginList({ pluginInfo, pluginType_ }) {
  const plugin = `${pluginType_}s`;
  return (
    <div>
      <h6 className="text-secondary text-capitalize">{plugin} &nbsp;</h6>
      <ul>
        {pluginInfo[plugin].map((pluginName) => (
          <li
            key={`plugininfocard-${pluginType_}__${pluginInfo.name}-${pluginName}`}
          >
            <span>{pluginName}</span>
            {pluginInfo?.runtime_configuration[plugin][pluginName] !==
              undefined &&
              Object.keys(pluginInfo?.runtime_configuration[plugin][pluginName])
                .length !== 0 && (
                <ul>
                  <b>Parameters:</b>
                  <li style={{ listStyleType: "square" }}>
                    <code>
                      {JSON.stringify(
                        pluginInfo?.runtime_configuration[plugin][pluginName],
                        null,
                        2,
                      )}
                    </code>
                  </li>
                </ul>
              )}
          </li>
        ))}
      </ul>
    </div>
  );
}

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

PlaybooksCollapse.propTypes = {
  pluginList: PropTypes.array.isRequired,
  pluginType_: PropTypes.oneOf(Object.values(PluginsTypes)).isRequired,
};

PlaybookPluginList.propTypes = {
  pluginInfo: PropTypes.object.isRequired,
  pluginType_: PropTypes.oneOf(Object.values(PluginsTypes)).isRequired,
};
