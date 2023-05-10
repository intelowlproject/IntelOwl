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
  // link added only in case is available and the component is not disabled, or it will be clickable
  if (link && !disable) {
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
      className={`${disable ? "opacity-25" : ""} ${className}`}
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
