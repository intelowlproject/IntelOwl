import React from "react";
import PropTypes from "prop-types";
import { Button, UncontrolledTooltip, Badge } from "reactstrap";
import { CgListTree } from "react-icons/cg";
import { fromZonedTime } from "date-fns-tz";
import { LuCalendarSearch } from "react-icons/lu";
import { RiBarChartHorizontalFill } from "react-icons/ri";

import { DropdownNavLink } from "@certego/certego-ui";

import { localTimezone } from "../../../../constants/miscConst";

export function InvestigationOverviewButton({ id, name }) {
  return (
    <Button
      className="bg-body border-1 border-primary lh-sm me-1 d-flex align-items-center"
      href={`/investigation/${id}`}
      target="_blank"
      rel="noreferrer"
      id="investigationOverviewBtn"
      size="xs"
      style={{ fontSize: "0.8rem" }}
    >
      <CgListTree className="me-1" />
      Investigation
      <UncontrolledTooltip placement="top" target="investigationOverviewBtn">
        Go to investigation: {name}
      </UncontrolledTooltip>
    </Button>
  );
}

InvestigationOverviewButton.propTypes = {
  id: PropTypes.number.isRequired,
  name: PropTypes.string.isRequired,
};

export function RelatedInvestigationButton({
  name,
  relatedInvestigationNumber,
}) {
  const investigationTimeRange = 30;
  const endDateRelatedInvestigation = new Date();
  const startDateRelatedInvestigation = structuredClone(
    endDateRelatedInvestigation,
  );
  startDateRelatedInvestigation.setDate(
    startDateRelatedInvestigation.getDate() - investigationTimeRange,
  );

  const url = `/history/investigations?start_time__gte=${encodeURIComponent(
    fromZonedTime(startDateRelatedInvestigation, localTimezone).toISOString(),
  )}&start_time__lte=${encodeURIComponent(
    fromZonedTime(endDateRelatedInvestigation, localTimezone).toISOString(),
  )}&analyzed_object_name=${name}&ordering=-start_time`;

  return (
    <DropdownNavLink
      to={url}
      target="_blank"
      className="d-flex align-items-center text-light"
    >
      <LuCalendarSearch className="me-1 text-info" /> Related investigations:{" "}
      <Badge className="ms-1 bg-info">{relatedInvestigationNumber || 0}</Badge>
    </DropdownNavLink>
  );
}

RelatedInvestigationButton.propTypes = {
  name: PropTypes.string.isRequired,
  relatedInvestigationNumber: PropTypes.number.isRequired,
};

export function AnalyzableOverviewButton({ id }) {
  return (
    <Button
      className="bg-accent-2 border-0 lh-sm me-1 d-flex align-items-center"
      href={`/artifacts/${id}`}
      target="_blank"
      rel="noreferrer"
      id="analyzableOverviewBtn"
      size="xs"
      style={{ fontSize: "0.8rem" }}
    >
      <RiBarChartHorizontalFill className="me-1" />
      Artifact
      <UncontrolledTooltip placement="top" target="analyzableOverviewBtn">
        Artifact overview
      </UncontrolledTooltip>
    </Button>
  );
}

AnalyzableOverviewButton.propTypes = {
  id: PropTypes.number.isRequired,
};
