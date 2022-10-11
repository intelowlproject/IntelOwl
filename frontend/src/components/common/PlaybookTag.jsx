import React from "react";
import PropTypes from "prop-types";
import { Badge } from "reactstrap";

export default function PlaybookTag(props) {
  const { playbook, ...rest } = props;

  return (
    <Badge color="black" {...rest}>
      {playbook}
    </Badge>
  );
}

PlaybookTag.propTypes = {
  playbook: PropTypes.string.isRequired,
};
