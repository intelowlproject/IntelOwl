import React from "react";
import PropTypes from "prop-types";

export function TitleVisualizer({ title, value }) {
  return (
    <div className="d-flex flex-column align-items-center">
      <div className="mb-1 text-capitalize">{title}</div>
      <div className="p-1 d-inline-flex">{value}</div>
    </div>
  );
}

TitleVisualizer.propTypes = {
  title: PropTypes.element.isRequired,
  value: PropTypes.element.isRequired,
};
