import React from "react";
import PropTypes from "prop-types";

import { BaseVisualizer } from "./base";
import { getIcon } from "../icons";

export function IconVisualizer({
  icon,
  color,
  link,
  className,
  additionalElements,
  hideIfEmpty,
  disableIfEmpty,
}) {
  if (hideIfEmpty && !icon) {
    return null;
  }
  let isDisabled = "";
  if (disableIfEmpty && !icon) {
    isDisabled = "visualizer-element-disabled";
  }
  return (
    <div key={icon} className="col-auto">
      <BaseVisualizer
        value={getIcon(icon)}
        color={color}
        link={link}
        className={`fw-bold border border-primary rounded p-1 ${className} ${isDisabled}`}
        additionalElements={additionalElements}
      />
    </div>
  );
}

IconVisualizer.propTypes = {
  icon: PropTypes.string.isRequired,
  color: PropTypes.string,
  link: PropTypes.string,
  className: PropTypes.string,
  additionalElements: PropTypes.arrayOf(PropTypes.object),
  hideIfEmpty: PropTypes.bool,
  disableIfEmpty: PropTypes.bool,
};

IconVisualizer.defaultProps = {
  color: "",
  link: "",
  className: "",
  additionalElements: null,
  hideIfEmpty: false,
  disableIfEmpty: false,
};
