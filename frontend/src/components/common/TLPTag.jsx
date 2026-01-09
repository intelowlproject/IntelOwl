import React from "react";
import PropTypes from "prop-types";
import { Badge, UncontrolledTooltip } from "reactstrap";
import { TLPColors } from "../../constants/colorConst";
import { TLPDescriptions } from "../../constants/miscConst";
import { TlpChoices } from "../../constants/advancedSettingsConst";

export function TLPTag(props) {
  const { value, ...rest } = props;
  
  // Handle case where value is undefined/null
  if (!value) {
    return <Badge color="secondary">No TLP</Badge>;
  }
  
  const badgeId = `tlptag-badge__${value}`;
  const color = TLPColors?.[value] || "#dfe1e2";
  const tooltipText = TLPDescriptions?.[value] || "invalid";

  return (
    <Badge
      id={badgeId}
      color={null}
      style={{
        borderRadius: 5,
        userSelect: "none",
        backgroundColor: color,
        color: value === "CLEAR" ? "#000000" : "#FFFFFF",
        fontWeight: "bold",
      }}
      {...rest}
    >
      {value}
      <UncontrolledTooltip target={badgeId} placement="top" fade={false}>
        {tooltipText}
      </UncontrolledTooltip>
    </Badge>
  );
}

TLPTag.propTypes = {
  value: PropTypes.oneOf(TlpChoices).isRequired,
};
