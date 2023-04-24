import React from "react";
import PropTypes from "prop-types";

export function TitleVisualizer({ title, value, disable }) {
  return (
    <div
      className={`d-flex flex-column align-items-center ${
        disable ? "visualizer-element-disabled" : ""
      }`}
    >
      <div className="mb-1 text-capitalize">{title}</div>
      <div className="p-1 d-inline-flex">{value}</div>
    </div>
  );
}

TitleVisualizer.propTypes = {
  title: PropTypes.element.isRequired,
  value: PropTypes.element.isRequired,
  disable: PropTypes.bool,
};

TitleVisualizer.defaultProps = {
  disable: false,
};
