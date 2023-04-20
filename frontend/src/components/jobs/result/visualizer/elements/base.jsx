import React from "react";
import PropTypes from "prop-types";

export function BaseVisualizer({
  value,
  icon,
  color,
  link,
  bold,
  italic,
  className,
  hideIfEmpty,
  disableIfEmpty,
}) {
  if (hideIfEmpty && !value && !icon) {
    return null;
  }
  let isDisabled = "";
  if (disableIfEmpty && !value && !icon) {
    isDisabled = "visualizer-element-disabled";
  }
  let coreComponent = (
    <p
      className={`mb-0 ${color} ${bold ? "fw-bold" : ""} ${
        italic ? "fst-italic" : ""
      }`}
    >
      {value} {icon}
    </p>
  );
  if (link) {
    coreComponent = (
      <a href={link} target="_blank" rel="noreferrer">
        {coreComponent}
      </a>
    );
  }
  return (
    <div
      className={`small d-flex align-items-center ${isDisabled} ${className} ${color}`}
    >
      {coreComponent}
    </div>
  );
}

BaseVisualizer.propTypes = {
  value: PropTypes.string.isRequired,
  icon: PropTypes.string,
  color: PropTypes.string,
  link: PropTypes.string,
  bold: PropTypes.bool,
  italic: PropTypes.bool,
  className: PropTypes.string,
  hideIfEmpty: PropTypes.bool,
  disableIfEmpty: PropTypes.bool,
};

BaseVisualizer.defaultProps = {
  icon: "",
  color: "",
  link: "",
  bold: false,
  italic: false,
  className: "",
  hideIfEmpty: false,
  disableIfEmpty: false,
};
