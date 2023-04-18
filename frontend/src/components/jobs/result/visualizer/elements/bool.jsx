import React from "react";
import PropTypes from "prop-types";

import { Badge } from "reactstrap";

export function BooleanVisualizer({
  name,
  value,
  pill,
  link,
  className,
  activeColor,
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
  let coreComponent = <p className="mb-0">{name}</p>;
  if (link) {
    coreComponent = (
      <a href={link} target="_blank" rel="noreferrer">
        {coreComponent}
      </a>
    );
  }
  return (
    <div key={`${name}__${value}`} className="col-auto">
      <Badge
        pill={pill}
        color={value === true ? activeColor : "gray"}
        className={`text-capitalize ${isDisabled} ${className}`}
      >
        <div className="d-flex align-items-center">{coreComponent}</div>
      </Badge>
    </div>
  );
}

BooleanVisualizer.propTypes = {
  name: PropTypes.string.isRequired,
  value: PropTypes.bool.isRequired,
  pill: PropTypes.bool,
  link: PropTypes.string,
  className: PropTypes.string,
  activeColor: PropTypes.string,
  hideIfEmpty: PropTypes.bool,
  disableIfEmpty: PropTypes.bool,
};

BooleanVisualizer.defaultProps = {
  pill: true,
  link: "",
  className: "",
  activeColor: "danger",
  hideIfEmpty: false,
  disableIfEmpty: false,
};
