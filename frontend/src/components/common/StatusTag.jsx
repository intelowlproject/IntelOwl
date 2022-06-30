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
    <span className={divClass} title={status} {...rest}>
      {status.toUpperCase()}
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
