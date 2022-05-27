import React from "react";
import PropTypes from "prop-types";
import { Badge } from "reactstrap";

export default function JobTag(props) {
  const { tag, ...rest } = props;

  return (
    <Badge
      color={null}
      style={{
        backgroundColor: tag.color,
      }}
      {...rest}
    >
      {tag.label}
    </Badge>
  );
}

JobTag.propTypes = {
  tag: PropTypes.shape({
    label: PropTypes.string.isRequired,
    color: PropTypes.string.isRequired,
  }).isRequired,
};
