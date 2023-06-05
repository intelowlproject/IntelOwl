import React from "react";
import PropTypes from "prop-types";

export function BaseVisualizer({
  size,
  alignment,
  value,
  icon,
  color,
  link,
  bold,
  italic,
  disable,
}) {
  let coreComponent = (
    <span
      className={`${color} ${bold ? "fw-bold" : ""} ${
        italic ? "fst-italic" : ""
      }`}
    >
      {value} {icon}
    </span>
  );
  // link added only in case is available and the component is not disabled, or it will be clickable
  if (link && !disable) {
    coreComponent = (
      <a href={link} target="_blank" rel="noreferrer">
        {coreComponent}
      </a>
    );
  }
  return (
    <div
      className={`${size} small d-flex align-items-center text-${alignment} justify-content-${alignment} ${
        disable ? "opacity-25" : ""
      } ${color}`}
    >
      {coreComponent}
    </div>
  );
}

BaseVisualizer.propTypes = {
  size: PropTypes.string.isRequired,
  value: PropTypes.string.isRequired,
  alignment: PropTypes.string,
  icon: PropTypes.object,
  color: PropTypes.string,
  link: PropTypes.string,
  bold: PropTypes.bool,
  italic: PropTypes.bool,
  disable: PropTypes.bool,
};

BaseVisualizer.defaultProps = {
  icon: undefined,
  alignment: "center",
  color: "",
  link: "",
  bold: false,
  italic: false,
  disable: false,
};
