import React from "react";
import PropTypes from "prop-types";
import classnames from "classnames";
import { UncontrolledTooltip, Button, Collapse } from "reactstrap";
import {
  BooleanIcon,
  ArrowToggleIcon,
  CopyToClipboardButton,
} from "@certego/certego-ui";
import { PluginsTypes } from "../../../constants/pluginConst";

// NON PIÙ USATA
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
