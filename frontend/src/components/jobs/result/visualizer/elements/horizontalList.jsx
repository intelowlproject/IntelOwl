import React from "react";
import PropTypes from "prop-types";
import { Row } from "reactstrap";

export function HorizontalListVisualizer({ values, alignment, id }) {
  return (
    <Row className={`align-items-start justify-content-${alignment}`} id={id}>
      {values}
    </Row>
  );
}

HorizontalListVisualizer.propTypes = {
  values: PropTypes.arrayOf(PropTypes.element).isRequired,
  alignment: PropTypes.string,
  id: PropTypes.string.isRequired,
};

HorizontalListVisualizer.defaultProps = {
  alignment: "around",
};
