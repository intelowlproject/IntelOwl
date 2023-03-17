import React from "react";
import PropTypes from "prop-types";

export function BaseVisualizerField({
  value,
  color,
  link,
  className,
  additionalElements,
  hideIfEmpty,
  disableIfEmpty,
}) {
  if (hideIfEmpty && !value) {
    return null;
  }
  let isDisabled = "";
  if (disableIfEmpty && !value) {
    isDisabled = "visualizer-element-disabled";
  }
  let coreComponent = <p className={`mb-0 ${color}`}>{value}</p>;
  if (link) {
    coreComponent = (
      <a href={link} target="_blank" rel="noreferrer">
        {coreComponent}
      </a>
    );
  }
  return (
    <div key={value} className="col-auto">
      <div
        className={`small d-flex align-items-center ${isDisabled} ${className} ${color}`}
      >
        {coreComponent}
        {additionalElements && (
          <div className="mx-1 d-flex align-items-center">
            {additionalElements}
          </div>
        )}
      </div>
    </div>
  );
}

BaseVisualizerField.propTypes = {
  value: PropTypes.string.isRequired,
  color: PropTypes.string,
  link: PropTypes.string,
  className: PropTypes.string,
  additionalElements: PropTypes.arrayOf(PropTypes.object),
  hideIfEmpty: PropTypes.bool,
  disableIfEmpty: PropTypes.bool,
};

BaseVisualizerField.defaultProps = {
  color: "",
  link: "",
  className: "",
  additionalElements: null,
  hideIfEmpty: false,
  disableIfEmpty: false,
};
