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
  disable,
}) {
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
      className={`small d-flex align-items-center ${
        disable ? "visualizer-element-disabled" : ""
      } ${className} ${color}`}
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
  disable: PropTypes.bool,
};

BaseVisualizer.defaultProps = {
  icon: "",
  color: "",
  link: "",
  bold: false,
  italic: false,
  className: "",
  disable: false,
};
