import React from "react";
import PropTypes from "prop-types";
import { Badge } from "reactstrap";

import { DateHoverable } from "@certego/certego-ui";

export function UserReportDecay(props) {
  const { decay, reliability } = props;

  let decayedElement = null;
  if (decay === null && reliability === 0) {
    decayedElement = <Badge color="accent">Decayed</Badge>;
  } else if (decay !== null && decay !== undefined) {
    decayedElement = (
      <DateHoverable
        ago
        noHover
        value={decay}
        format="hh:mm:ss a MMM do, yyyy"
      />
    );
  }
  return decayedElement;
}

UserReportDecay.propTypes = {
  decay: PropTypes.any.isRequired,
  reliability: PropTypes.number.isRequired,
};
