import React from "react";
import PropTypes from "prop-types";

export function TitleVisualizer({ size, title, value }) {
  return (
    <div className={`${size} d-flex flex-column align-items-center`}>
      <div className="mb-1 text-capitalize">{title}</div>
      <div className="p-1">{value}</div>
    </div>
  );
}

TitleVisualizer.propTypes = {
  size: PropTypes.string.isRequired,
  title: PropTypes.element.isRequired,
  value: PropTypes.element.isRequired,
};
