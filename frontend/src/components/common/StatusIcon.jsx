import React from "react";
import PropTypes from "prop-types";
import classnames from "classnames";
import {
  MdCircle,
  MdOutlinePending,
  MdCheckCircleOutline,
  MdWarningAmber,
  MdOutlineBlock,
} from "react-icons/md";
import { IoMdCloseCircleOutline } from "react-icons/io";
import { RiLoader2Fill } from "react-icons/ri";

import { UncontrolledTooltip } from "reactstrap";
import { STATUS_COLORMAP } from "../../constants";

const STATUS_ICON_MAP = {
  pending: MdOutlinePending,
  running: RiLoader2Fill,
  reported_with_fails: MdWarningAmber,
  success: MdCheckCircleOutline,
  reported_without_fails: MdCheckCircleOutline,
  killed: MdOutlineBlock,
  failed: IoMdCloseCircleOutline,
};

export default function StatusIcon(props) {
  const { status, className, ...rest } = props;

  const statusLower = status.toLowerCase();

  const color = STATUS_COLORMAP?.[statusLower] || "light";
  const Icon = STATUS_ICON_MAP?.[statusLower] || MdCircle;
  const iconClassName = classnames(`text-${color}`, className);

  return (
    <>
      <Icon
        id={`statusicon-${statusLower}`}
        className={iconClassName}
        {...rest}
      />
      <UncontrolledTooltip
        target={`statusicon-${statusLower}`}
        trigger="hover"
        className="p-0 m-0"
      >
        {statusLower}
      </UncontrolledTooltip>
    </>
  );
}

StatusIcon.propTypes = {
  status: PropTypes.string.isRequired,
  className: PropTypes.string,
};

StatusIcon.defaultProps = {
  className: null,
};
