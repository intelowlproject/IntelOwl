import React from "react";
import PropTypes from "prop-types";
import { CopyToClipboardButton } from "@certego/certego-ui";

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
}) {
  let coreComponent = (
    <span
      className={`${color} ${bold ? "fw-bold" : ""} ${
        italic ? "fst-italic" : ""
      }`}
    >
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

  const copyButton = !(
    id.split("-").indexOf("vlist") !== -1 ||
    id.split("-").indexOf("title") !== -1
  );

  return (
    <div
      className={`${size} small d-flex align-items-center text-${alignment} justify-content-${alignment} ${
        disable ? "opacity-25" : ""
      } ${color}`}
      id={id}
    >
      {copyButton ? (
        <CopyToClipboardButton id={`${id}`} text={copyText || value}>
          {coreComponent}
        </CopyToClipboardButton>
      ) : (
        coreComponent
      )}
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
};
