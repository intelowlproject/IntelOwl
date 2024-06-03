import React from "react";
import PropTypes from "prop-types";
import { UncontrolledTooltip } from "reactstrap";
import { VscGlobe, VscFile } from "react-icons/vsc";

import { extractCountry } from "./utils/extractCountry";
import { getIcon } from "./visualizer/icons";
import { ObservableClassifications } from "../../../constants/jobConst";

export function JobInfoIcon({ job }) {
  let iconElement;
  const country = extractCountry(job);
  const countryIcon = getIcon(country.countryCode);

  // file
  if (job.is_sample) iconElement = <VscFile className="me-1" />;
  // ip with country flag
  else if (
    job.observable_classification === ObservableClassifications.IP &&
    country.countryCode
  ) {
    iconElement = (
      <span className="px-1">
        {countryIcon}
        <UncontrolledTooltip
          placement="right"
          target={`Icon-${country.countryCode.toLowerCase()}`}
        >
          {country.countryName}
        </UncontrolledTooltip>
      </span>
    );
  } else {
    iconElement = <VscGlobe className="me-1" />;
  }
  return iconElement;
}

JobInfoIcon.propTypes = {
  job: PropTypes.object.isRequired,
};
