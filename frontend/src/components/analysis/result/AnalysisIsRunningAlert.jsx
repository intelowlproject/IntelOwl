import React from "react";
import PropTypes from "prop-types";
import { Fade } from "reactstrap";

import { IconAlert } from "@certego/certego-ui";

export function AnalysisIsRunningAlert({ analysis }) {
  console.debug(analysis);

  return (
    <Fade className="d-flex-center mx-auto">
      <IconAlert
        id="analysisisrunningalert-iconalert"
        color="info"
        className="text-info text-center"
      >
        <h6>
          This analysis is currently{" "}
          <strong className="text-accent">running</strong>.
        </h6>
        <div className="text-gray">
          The page will auto-refresh once the analysis completes. You can either
          wait here or come back later and check.
        </div>
      </IconAlert>
    </Fade>
  );
}

AnalysisIsRunningAlert.propTypes = {
  analysis: PropTypes.object.isRequired,
};
