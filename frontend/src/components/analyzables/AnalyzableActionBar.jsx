import React from "react";
import PropTypes from "prop-types";

import { ContentSection, IconButton } from "@certego/certego-ui";

import { rescanIcon } from "../common/icon/actionIcons";

export function AnalyzableActionsBar({ analyzable }) {
  return (
    <ContentSection className="d-inline-flex me-2">
      <IconButton
        id="rescanbtn"
        Icon={rescanIcon}
        size="sm"
        color="light"
        title="Rescan analyzable"
        titlePlacement="top"
        href={`/scan?observable=${analyzable.name}`}
        target="_blank"
        rel="noreferrer"
      />
    </ContentSection>
  );
}

AnalyzableActionsBar.propTypes = {
  analyzable: PropTypes.object.isRequired,
};
