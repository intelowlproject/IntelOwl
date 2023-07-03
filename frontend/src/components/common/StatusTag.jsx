import React from "react";
import PropTypes from "prop-types";
import classnames from "classnames";
import { STATUS_COLORMAP } from "../../constants";

export default function StatusTag(props) {
  const { status, className, ...rest } = props;

  const statusLower = status.toLowerCase();

  const color = STATUS_COLORMAP?.[statusLower] || "light";
  const divClass = classnames(`bg-${color}`, className);

  return (
    <div className={`p-1 ${divClass}`}>
      <span
        className="text-break text-center status-tag"
        title={status}
        {...rest}
      >
        {status.toUpperCase().replaceAll("_", " ")}
      </span>
    </div>
  );
}

StatusTag.propTypes = {
  status: PropTypes.string.isRequired,
  className: PropTypes.string,
};

StatusTag.defaultProps = {
  className: null,
};
