import React from "react";
import PropTypes from "prop-types";

import { Badge } from "reactstrap";

export function BooleanVisualizer({
  size,
  name,
  value,
  link,
  icon,
  italic,
  className,
  activeColor,
  disable,
}) {
  let coreComponent = (
    <span className={`${italic ? "fst-italic" : ""}`}>
      {name} {icon}
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
    <div className={`${size}`}>
      <Badge
        pill
        color={value === true ? activeColor : "gray"}
        className={`w-100 text-wrap ${
          disable ? "opacity-25" : ""
        } ${className}`}
      >
        {coreComponent}
      </Badge>
    </div>
  );
}

BooleanVisualizer.propTypes = {
  size: PropTypes.string.isRequired,
  name: PropTypes.string.isRequired,
  value: PropTypes.bool.isRequired,
  link: PropTypes.string,
  icon: PropTypes.string,
  italic: PropTypes.bool,
  className: PropTypes.string,
  activeColor: PropTypes.string,
  disable: PropTypes.bool,
};

BooleanVisualizer.defaultProps = {
  link: "",
  icon: "",
  italic: false,
  className: "",
  activeColor: "danger",
  disable: false,
};
