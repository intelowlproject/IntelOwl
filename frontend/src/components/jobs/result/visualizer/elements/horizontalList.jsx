import React from "react";
import PropTypes from "prop-types";
import { Row } from "reactstrap";

export function HorizontalListVisualizer({ values }) {
  return (
    <Row className="align-items-center justify-content-around">{values}</Row>
  );
}

HorizontalListVisualizer.propTypes = {
  values: PropTypes.arrayOf(PropTypes.element).isRequired,
};
