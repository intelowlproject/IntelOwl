import React from "react";
import { Modal, ModalHeader, ModalBody } from "reactstrap";
import PropTypes from "prop-types";

import { UserEventForm } from "./UserEventForm";
import { DataModelEvaluations } from "../../constants/dataModelConst";
import { DecayProgressionTypes } from "../../constants/userEventsConst";

const EMPTY_FORM = Object.freeze({
  // base data model fields
  analyzables: [""],
  basic_evaluation: "0",
  kill_chain_phase: "",
  external_references: [""],
  reason: "",
  related_threats: [""],
  tags: [],
  malware_family: "",
  // advanced fields
  evaluation: DataModelEvaluations.MALICIOUS,
  reliability: 10,
  decay_progression: DecayProgressionTypes.LINEAR,
  decay_timedelta_days: 120,
});

export function UserEventModal({
  analyzables,
  toggle,
  isOpen,
  onSubmitCallback,
}) {
  console.debug("UserEventModal rendered!");

  const initialFormValues = JSON.parse(JSON.stringify(EMPTY_FORM));
  if (analyzables?.length > 0) {
    initialFormValues.analyzables = analyzables.map(
      (analyzable) => analyzable?.name || "",
    );
  }

  return (
    <Modal
      id="user-evaluation-modal"
      autoFocus
      centered
      zIndex="1050"
      size="lg"
      backdrop="static"
      labelledBy="User evaluation modal"
      isOpen={isOpen}
      style={{ minWidth: "80%" }}
      toggle={() => {
        toggle(false);
      }}
    >
      <ModalHeader
        className="mx-2"
        toggle={() => {
          toggle(false);
        }}
      >
        <small className="text-info">Add your evaluation</small>
      </ModalHeader>
      <ModalBody className="m-2">
        <UserEventForm
          initialFormValues={initialFormValues}
          toggle={toggle}
          onSubmitCallback={onSubmitCallback}
        />
      </ModalBody>
    </Modal>
  );
}

UserEventModal.propTypes = {
  analyzables: PropTypes.array,
  toggle: PropTypes.func.isRequired,
  isOpen: PropTypes.bool.isRequired,
  onSubmitCallback: PropTypes.func,
};

UserEventModal.defaultProps = {
  analyzables: [""],
  onSubmitCallback: undefined,
};
