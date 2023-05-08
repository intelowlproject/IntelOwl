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
      className={`small d-flex align-items-center ${
        disable ? "opacity-25" : ""
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
