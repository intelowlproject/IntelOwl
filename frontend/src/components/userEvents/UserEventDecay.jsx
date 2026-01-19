import React from "react";
import PropTypes from "prop-types";
import { Badge } from "reactstrap";

import { DateHoverable } from "@certego/certego-ui";

export function UserEventDecay(props) {
  const { decay, reliability } = props;

  let decayComponent = null;
  if (decay === null && reliability === 0) {
    decayComponent = <Badge color="accent">Decayed</Badge>;
  } else if (decay !== null && decay !== undefined) {
    decayComponent = (
      <DateHoverable
        ago
        noHover
        value={decay}
        format="hh:mm:ss a MMM do, yyyy"
      />
    );
  }
  return decayComponent;
}

UserEventDecay.propTypes = {
  decay: PropTypes.any.isRequired,
  reliability: PropTypes.number.isRequired,
};
