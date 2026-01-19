import React from "react";
import PropTypes from "prop-types";

export function TitleVisualizer({ size, title, value, alignment, id }) {
  return (
    <div
      className={`${size} d-flex flex-column align-items-${alignment}`}
      id={id}
    >
      <div className="mb-1 text-capitalize">{title}</div>
      {value}
    </div>
  );
}

TitleVisualizer.propTypes = {
  size: PropTypes.string.isRequired,
  title: PropTypes.element.isRequired,
  value: PropTypes.element.isRequired,
  alignment: PropTypes.string,
  id: PropTypes.string.isRequired,
};

TitleVisualizer.defaultProps = {
  alignment: "center",
};
