import React from "react";
import PropTypes from "prop-types";

import { Badge } from "reactstrap";
import { VisualizerTooltip } from "../VisualizerTooltip";

export function BooleanVisualizer({
  size,
  value,
  link,
  icon,
  italic,
  activeColor,
  disable,
  id,
  copyText,
  description,
}) {
  let coreComponent = (
    <React.Fragment>
      {icon}
      <span className={italic ? "fst-italic" : ""} id={`${id}-tooltip`}>
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
    <div className={size} id={id}>
      <Badge
        pill
        color={disable ? "gray" : activeColor}
        className={`w-100 text-wrap text-capitalize ${
          disable ? "opacity-25" : ""
        }`}
      >
        {coreComponent}
      </Badge>
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

BooleanVisualizer.propTypes = {
  size: PropTypes.string.isRequired,
  value: PropTypes.string.isRequired,
  link: PropTypes.string,
  icon: PropTypes.object,
  italic: PropTypes.bool,
  activeColor: PropTypes.string,
  disable: PropTypes.bool,
  id: PropTypes.string.isRequired,
  copyText: PropTypes.string,
  description: PropTypes.string,
};

BooleanVisualizer.defaultProps = {
  link: "",
  icon: undefined,
  italic: false,
  activeColor: "danger",
  disable: false,
  description: "",
  copyText: "",
};
