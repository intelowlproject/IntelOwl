import React from "react";
import PropTypes from "prop-types";
import { Row } from "reactstrap";

export function HorizontalListVisualizer({ values, alignment }) {
  return (
    <Row className={`align-items-start justify-content-${alignment}`}>
      {values}
    </Row>
  );
}

HorizontalListVisualizer.propTypes = {
  values: PropTypes.arrayOf(PropTypes.element).isRequired,
  alignment: PropTypes.string,
};

HorizontalListVisualizer.defaultProps = {
  alignment: "around",
};
