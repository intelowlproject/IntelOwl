import React from "react";
import PropTypes from "prop-types";

import { ContentSection, IconButton } from "@certego/certego-ui";

import { rescanIcon, addEvaluationIcon } from "../../common/icon/actionIcons";
import { UserReportModal } from "../../userReports/UserReportModal";

export function AnalyzableActionsBar({ analyzable }) {
  const [showUserReportModal, setShowUserReportModal] = React.useState(false);

  return (
    <ContentSection className="d-inline-flex me-2">
      <IconButton
        id="addUserEvaluationBtn"
        Icon={addEvaluationIcon}
        size="sm"
        color="secondary"
        title="Add your evaluation"
        titlePlacement="top"
        className="me-2"
        onClick={() => setShowUserReportModal(!showUserReportModal)}
      />
      {showUserReportModal && (
        <UserReportModal
          analyzables={[analyzable]}
          toggle={setShowUserReportModal}
          isOpen={showUserReportModal}
        />
      )}
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
