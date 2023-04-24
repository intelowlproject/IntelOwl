import React from "react";
import PropTypes from "prop-types";

import { Badge } from "reactstrap";

export function BooleanVisualizer({
  name,
  value,
  link,
  className,
  activeColor,
  disable,
}) {
  let coreComponent = <p className="mb-0">{name}</p>;
  if (link) {
    coreComponent = (
      <a href={link} target="_blank" rel="noreferrer">
        {coreComponent}
      </a>
    );
  }
  return (
    <Badge
      pill
      color={value === true ? activeColor : "gray"}
      className={`${disable ? "visualizer-element-disabled" : ""} ${className}`}
    >
      <div className="d-flex align-items-center">{coreComponent}</div>
    </Badge>
  );
}

BooleanVisualizer.propTypes = {
  name: PropTypes.string.isRequired,
  value: PropTypes.bool.isRequired,
  link: PropTypes.string,
  className: PropTypes.string,
  activeColor: PropTypes.string,
  disable: PropTypes.bool,
};

BooleanVisualizer.defaultProps = {
  link: "",
  className: "",
  activeColor: "danger",
  disable: false,
};
