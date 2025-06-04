import React from "react";
import PropTypes from "prop-types";
// import axios from "axios";

import { ContentSection, IconButton } from "@certego/certego-ui";

import { rescanIcon } from "../../common/icon/actionIcons";
// import { USER_EVENT_ANALYZABLE } from "../../../constants/apiURLs";
// import {prettifyErrors} from "../../../utils/api";

export function AnalyzableActionsBar({ analyzable }) {
  return (
    <ContentSection className="d-inline-flex me-2">
      {/* <IconButton
        id="addUserReportBtn"
        Icon={()=>"Add your report"}
        size="sm"
        color="secondary"
        title="Add your report"
        titlePlacement="top"
        className="me-2"
        onClick={()=>addUserReport(analyzable.id)}
      /> */}
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
