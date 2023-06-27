import React from "react";
import PropTypes from "prop-types";

import { Badge } from "reactstrap";
import { CopyToClipboardButton } from "@certego/certego-ui";

export function BooleanVisualizer({
  size,
  value,
  link,
  icon,
  italic,
  activeColor,
  disable,
  id,
}) {
  let coreComponent = (
    <span className={`${italic ? "fst-italic" : ""}`}>
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
    <div className={`${size}`}>
      <Badge
        pill
        color={disable ? "gray" : activeColor}
        className={`w-100 text-wrap ${disable ? "opacity-25" : ""}`}
      >
        <CopyToClipboardButton id={`${id}`} text={value}>
          {coreComponent}
        </CopyToClipboardButton>
      </Badge>
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
  id: PropTypes.number.isRequired,
};

BooleanVisualizer.defaultProps = {
  link: "",
  icon: undefined,
  italic: false,
  activeColor: "danger",
  disable: false,
};
