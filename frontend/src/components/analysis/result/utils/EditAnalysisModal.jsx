import React from "react";
import PropTypes from "prop-types";
import { Modal, ModalHeader, ModalBody, Button } from "reactstrap";

import { ContentSection } from "@certego/certego-ui";

import { updateAnalysis } from "../analysisApi";

// components
export function EditAnalysisModal(props) {
  const { isOpen, toggle, analysisId, field, ...rest } = props;

  console.debug("EditAnalysisModal rendered");

  const saveAndCloseModal = async () => {
    const data = {};
    const success = await updateAnalysis(analysisId, data);
    if (!success) return;
    toggle();
  };

  return (
    <Modal
      autoFocus
      zIndex="1050"
      size="m"
      isOpen={isOpen}
      toggle={toggle}
      keyboard={false}
      scrollable
      backdrop="static"
      labelledBy="Edit Analysis"
      {...rest}
    >
      <ModalHeader className="bg-tertiary" toggle={toggle}>
        Edit Analysis {field}
      </ModalHeader>
      <ModalBody
        className="d-flex-start-start bg-body"
        id="edit_analysis-ModalBody"
      >
        <ContentSection
          className="bg-darker"
          id="edit_runtime_configuration-section"
          style={{ maxHeight: "590px", overflowY: "auto" }}
        >
          <div className="mt-2 d-flex align-items-center justify-content-end">
            <Button
              onClick={saveAndCloseModal}
              size="sm"
              color="info"
              className="ms-2"
            >
              Save & Close
            </Button>
          </div>
        </ContentSection>
      </ModalBody>
    </Modal>
  );
}

EditAnalysisModal.propTypes = {
  isOpen: PropTypes.bool.isRequired,
  toggle: PropTypes.func.isRequired,
  analysisId: PropTypes.number.isRequired,
  field: PropTypes.string.isRequired,
};
