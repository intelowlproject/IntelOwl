import React from "react";
import PropTypes from "prop-types";

import { CustomMapBadge } from "@certego/certego-ui";

// constant
const INVITATION_STATUS_COLOR_MAP = {
  pending: "warning",
  accepted: "success",
  declined: "danger",
};

export default function InvitationStatusBadge({ status, ...rest }) {
  return (
    <CustomMapBadge
      status={status}
      statusColorMap={INVITATION_STATUS_COLOR_MAP}
      {...rest}
    />
  );
}

InvitationStatusBadge.propTypes = {
  status: PropTypes.string.isRequired,
};
