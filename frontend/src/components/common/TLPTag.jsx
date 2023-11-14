import React from "react";
import PropTypes from "prop-types";
import { Badge, UncontrolledTooltip } from "reactstrap";
import { TLPColors } from "../../constants/colorConst";
import { TLPDescriptions } from "../../constants/miscConst";
import { TlpChoices } from "../../constants/advancedSettingsConst";

export function TLPTag(props) {
  const { value, ...rest } = props;
  const badgeId = `tlptag-badge__${value}`;
  const color = TLPColors?.[value] || "#dfe1e2";
  const tooltipText = TLPDescriptions?.[value] || "invalid";

  return value ? (
    <Badge
      id={badgeId}
      color={null}
      style={{
        backgroundColor: color,
        color: "black",
        borderRadius: 0,
        userSelect: "none",
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
