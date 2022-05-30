import React from "react";
import PropTypes from "prop-types";
import { Badge, UncontrolledTooltip } from "reactstrap";
import {
  TLP_CHOICES,
  TLP_COLOR_MAP,
  TLP_DESCRIPTION_MAP,
} from "../../constants";

export default function TLPTag(props) {
  const { value, ...rest } = props;
  const badgeId = `tlptag-badge__${value}`;
  const color = TLP_COLOR_MAP?.[value] || "#dfe1e2";
  const tooltipText = TLP_DESCRIPTION_MAP?.[value] || "invalid";

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
  value: PropTypes.oneOf(TLP_CHOICES).isRequired,
};
