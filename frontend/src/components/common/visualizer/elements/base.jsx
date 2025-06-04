import React from "react";
import PropTypes from "prop-types";
import { VisualizerTooltip } from "../VisualizerTooltip";

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
  id,
  copyText,
  isChild,
  description,
}) {
  let coreComponent = (
    <React.Fragment>
      {icon}
      <span
        className={`${isChild ? "small" : ""} ${color} ${
          bold ? "fw-bold" : ""
        } ${italic ? "fst-italic" : ""}`}
        id={`${id}-tooltip`}
      >
        {value}
      </span>
    </React.Fragment>
  );
  // link added only in case is available and the component is not disabled, or it will be clickable
  if (link && !disable) {
    coreComponent = (
      <div style={{ textDecoration: "underline dotted" }}>{coreComponent}</div>
    );
  }

  return (
    <div
      className={`${size} ${
        isChild ? "small" : ""
      } p-0 m-1 d-flex align-items-center text-${alignment} justify-content-${alignment} ${
        disable ? "opacity-25" : ""
      } ${color}`}
      id={id}
    >
      {coreComponent}
      <VisualizerTooltip
        idElement={`${id}-tooltip`}
        copyText={copyText}
        link={link}
        disable={disable}
        description={description}
      />
    </div>
  );
}

BaseVisualizer.propTypes = {
  size: PropTypes.string.isRequired,
  value: PropTypes.string.isRequired,
  id: PropTypes.string.isRequired,
  alignment: PropTypes.string,
  icon: PropTypes.object,
  color: PropTypes.string,
  link: PropTypes.string,
  bold: PropTypes.bool,
  italic: PropTypes.bool,
  disable: PropTypes.bool,
  copyText: PropTypes.string,
  isChild: PropTypes.bool,
  description: PropTypes.string,
};

BaseVisualizer.defaultProps = {
  icon: undefined,
  alignment: "center",
  color: "",
  link: "",
  bold: false,
  italic: false,
  disable: false,
  copyText: "",
  isChild: false,
  description: "",
};
