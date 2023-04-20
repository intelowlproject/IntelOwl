import React from "react";
import PropTypes from "prop-types";

export function TitleVisualizer({ title, value, hideIfEmpty, disableIfEmpty }) {
  if (hideIfEmpty && !value) {
    return null;
  }
  let isDisabled = "";
  if (disableIfEmpty && !value) {
    isDisabled = "visualizer-element-disabled";
  }
  return (
    <div className={`d-flex flex-column align-items-center ${isDisabled}`}>
      <div className="mb-1">{title}</div>
      <div className="p-1 d-inline-flex">{value}</div>
    </div>
  );
}

TitleVisualizer.propTypes = {
  title: PropTypes.element.isRequired,
  value: PropTypes.element.isRequired,
  hideIfEmpty: PropTypes.bool,
  disableIfEmpty: PropTypes.bool,
};

TitleVisualizer.defaultProps = {
  hideIfEmpty: false,
  disableIfEmpty: false,
};
