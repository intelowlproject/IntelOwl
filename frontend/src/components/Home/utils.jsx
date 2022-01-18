import React from "react";
import classnames from "classnames";
import PropTypes from "prop-types";

export function SvgScrollDownArrow({ className, ...props }) {
  return (
    <div
      className={classnames("animatedArrow-container", className)}
      {...props}
    >
      <div className="animatedArrow" />
      <div className="animatedArrow" />
      <div className="animatedArrow" />
    </div>
  );
}

SvgScrollDownArrow.propTypes = {
  className: PropTypes.string,
};

SvgScrollDownArrow.defaultProps = {
  className: null,
};
