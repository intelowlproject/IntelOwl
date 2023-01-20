import React from "react";
import PropTypes from "prop-types";
import classnames from "classnames";
import { STATUS_COLORMAP } from "../../constants";

export default function StatusTag(props) {
  const { status, className, ...rest } = props;

  const statusLower = status.toLowerCase();

  const color = STATUS_COLORMAP?.[statusLower] || "light";
  const divClass = classnames("status-tag", `bg-${color}`, className);

  return (
    <span className={`text-break ${divClass}`} title={status} {...rest}>
      {status.toUpperCase().replaceAll("_", " ")}
    </span>
  );
}

StatusTag.propTypes = {
  status: PropTypes.string.isRequired,
  className: PropTypes.string,
};

StatusTag.defaultProps = {
  className: null,
};
