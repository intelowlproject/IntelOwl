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
import { StatusColors } from "../../../constants/colorConst";
import { JobFinalStatuses } from "../../../constants/jobConst";
import { InvestigationStatuses } from "../../../constants/investigationConst";

const STATUS_ICON_MAP = {
  pending: MdOutlinePending,
  running: RiLoader2Fill,
  analyzers_running: RiLoader2Fill,
  connectors_running: RiLoader2Fill,
  pivots_running: RiLoader2Fill,
  visualizers_running: RiLoader2Fill,
  analyzers_completed: RiLoader2Fill,
  connectors_completed: RiLoader2Fill,
  pivots_completed: RiLoader2Fill,
  visualizers_completed: RiLoader2Fill,
  reported_with_fails: MdWarningAmber,
  reported_without_fails: MdCheckCircleOutline,
  success: MdCheckCircleOutline,
  killed: MdOutlineBlock,
  failed: IoMdCloseCircleOutline,
  concluded: MdCheckCircleOutline,
};

export function StatusIcon(props) {
  const { status, className, ...rest } = props;

  const statusLower = status.toLowerCase();

  const color = StatusColors?.[statusLower] || "light";
  const Icon = STATUS_ICON_MAP?.[statusLower] || MdCircle;
  const iconClassName = classnames(`text-${color}`, className);

  const statuses = Object.values(JobFinalStatuses).concat(
    Object.values(InvestigationStatuses),
  );

  return (
    <>
      <Icon
        id={`statusicon-${statusLower}`}
        className={iconClassName}
        {...rest}
      />
      {statuses.includes(statusLower) && (
        <UncontrolledTooltip
          target={`statusicon-${statusLower}`}
          trigger="hover"
          className="p-0 m-0"
        >
          {statusLower}
        </UncontrolledTooltip>
      )}
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
