import React from "react";
import PropTypes from "prop-types";
import { Button, Collapse } from "reactstrap";
import { ArrowToggleIcon, CopyToClipboardButton } from "@certego/certego-ui";
import { PluginsTypes } from "../../../constants/pluginConst";

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

PlaybooksCollapse.propTypes = {
  pluginList: PropTypes.array.isRequired,
  pluginType_: PropTypes.oneOf(Object.values(PluginsTypes)).isRequired,
};
