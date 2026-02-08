import React from "react";
import PropTypes from "prop-types";
import { Badge, UncontrolledTooltip } from "reactstrap";
import { TLPColors } from "../../constants/colorConst";
import { TLPDescriptions } from "../../constants/miscConst";
import { TlpChoices } from "../../constants/advancedSettingsConst";

let idCounter = 0;

export function TLPTag(props) {
  const { value, ...rest } = props;
  const uniqueId = React.useRef(idCounter).current;
  idCounter += 1;
  const badgeId = `tlptag-badge__${value}__${uniqueId}`;
  const color = TLPColors?.[value] || "#dfe1e2";
  const tooltipText = TLPDescriptions?.[value] || "invalid";
  const textColorMap = {
    CLEAR: "#000000",
    GREEN: "#000000",
    AMBER: "#000000",
  };
  const textColor = textColorMap[value] || "#FFFFFF";

  return value ? (
    <Badge
      id={badgeId}
      color={null}
      style={{
        borderRadius: 5,
        userSelect: "none",
        backgroundColor: color,
        border: `1px solid ${color}`,
        color: textColor,
      }}
      {...rest}
    >
      {value}
      <UncontrolledTooltip target={badgeId} placement="top" fade={false}>
        {tooltipText}
      </UncontrolledTooltip>
    </Badge>
  ) : null;
}

TLPTag.propTypes = {
  value: PropTypes.oneOf(TlpChoices).isRequired,
};
