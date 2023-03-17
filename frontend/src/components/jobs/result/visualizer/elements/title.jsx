import React from "react";
import PropTypes from "prop-types";

import { BaseVisualizerField } from "./base";

export function TitleVisualizerField({
  title,
  value,
  titleColor,
  titleLink,
  titleClassName,
  titleAdditionalElements,
  valueColor,
  valueLink,
  valueClassName,
  valueAdditionalElements,
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
  return (
    <div key={`${title}__${value}`} className="col-auto">
      <div className={`d-flex flex-column align-items-center ${isDisabled}`}>
        <div className="mb-1">
          <BaseVisualizerField
            value={title}
            color={titleColor}
            link={titleLink}
            className={`fw-bold ${titleClassName}`}
            additionalElements={titleAdditionalElements}
          />
        </div>
        <div className="p-1 d-inline-flex">
          <BaseVisualizerField
            value={value}
            color={valueColor}
            link={valueLink}
            className={valueClassName}
            additionalElements={valueAdditionalElements}
          />
        </div>
      </div>
    </div>
  );
}

TitleVisualizerField.propTypes = {
  title: PropTypes.string.isRequired,
  value: PropTypes.string.isRequired,
  titleColor: PropTypes.string,
  titleLink: PropTypes.string,
  titleClassName: PropTypes.string,
  titleAdditionalElements: PropTypes.arrayOf(PropTypes.object),
  valueColor: PropTypes.string,
  valueLink: PropTypes.string,
  valueClassName: PropTypes.string,
  valueAdditionalElements: PropTypes.arrayOf(PropTypes.object),
  hideIfEmpty: PropTypes.bool,
  disableIfEmpty: PropTypes.bool,
};

TitleVisualizerField.defaultProps = {
  titleColor: "",
  titleLink: "",
  titleClassName: "text-capitalize",
  titleAdditionalElements: null,
  valueColor: "bg-dark",
  valueLink: "",
  valueClassName: "",
  valueAdditionalElements: null,
  hideIfEmpty: false,
  disableIfEmpty: false,
};
