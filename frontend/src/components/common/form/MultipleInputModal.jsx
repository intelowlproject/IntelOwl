import React from "react";
import PropTypes from "prop-types";
import { Modal, ModalHeader, ModalBody, Button, Input } from "reactstrap";

import { ContentSection } from "@certego/certego-ui";
import { observableValidators } from "../../../utils/observables";

export function MultipleInputModal(props) {
  const { isOpen, toggle, formik, formikSetField, ...rest } = props;
  const [extractedObservables, setExtractedObservables] = React.useState({});

  const extractObservables = (inputText) => {
    // split text where there are spaces, breakline or , and ;
    const tokenizedText = inputText.split(/[,;\n\s]/);
    console.debug("tokenizedText", tokenizedText);

    const observables = {
      domain: [],
      ip: [],
      url: [],
      hash: [],
    };

    tokenizedText.forEach((string) => {
      const validationValue = observableValidators(string);
      if (validationValue.classification !== "generic")
        observables[validationValue.classification].push(
          validationValue.observable,
        );
    });

    // remove duplicates
    Object.keys(observables).forEach((key) => {
      observables[key] = [...new Set(observables[key])];
    });

    console.debug("MultipleInputModal - observables:");
    console.debug(observables);
    setExtractedObservables(observables);
  };

  const saveAndCloseModal = () => {
    const observableNames = Object.values(extractedObservables).flat();
    formik.setFieldValue(formikSetField, observableNames, false);
    toggle();
  };

  return (
    <Modal
      autoFocus
      zIndex="1050"
      size="xl"
      isOpen={isOpen}
      toggle={toggle}
      scrollable
      backdrop="static"
      labelledBy="Load Multiple Values"
      style={{ minWidth: "70%" }}
      {...rest}
    >
      <ModalHeader className="bg-tertiary" toggle={toggle}>
        Load Multiple Values
      </ModalHeader>
      <ModalBody
        className="d-flex-column bg-body"
        id="load_multiple_observables-ModalBody"
      >
        <div className="d-flex-start-start bg-body">
          <ContentSection
            className="bg-darker"
            id="load_multiple_observables-section"
            style={{ width: "60%" }}
          >
            <small className="text-muted mb-2">
              Enter any text to extract observables for further lookup.
            </small>
            <Input
              id="load_multiple_observables-textArea"
              name="textArea"
              type="textarea"
              onChange={(event) => extractObservables(event.target.value)}
              style={{ minHeight: "600px", overflowY: "auto" }}
              className="my-2"
            />
          </ContentSection>
          {/* lateral menu with the extracted observables */}
          <ContentSection className="ms-2 bg-darker" style={{ width: "40%" }}>
            <h5 className="text-accent">Extracted observables</h5>
            <div
              className="ps-4 pt-1 my-2"
              style={{ height: "600px", overflowY: "auto" }}
            >
              {Object.values(extractedObservables).flat().length === 0 ? (
                <small className="text-muted">No observable found.</small>
              ) : (
                Object.entries(extractedObservables).map(([key, iocs]) => (
                  <div>
                    <h6 key={key} className="text-secondary px-3">
                      {key}:
                    </h6>
                    <ul>
                      {iocs?.map((ioc) => (
                        <li key={`extractedObservables__${key}__${ioc}`}>
                          {ioc}
                        </li>
                      ))}
                    </ul>
                  </div>
                ))
              )}
            </div>
          </ContentSection>
        </div>
        <div className="d-flex justify-content-end mb-1">
          <Button
            disabled={Object.values(extractedObservables).flat().length === 0}
            onClick={saveAndCloseModal}
          >
            Extract
          </Button>
        </div>
      </ModalBody>
    </Modal>
  );
}

MultipleInputModal.propTypes = {
  isOpen: PropTypes.bool.isRequired,
  toggle: PropTypes.func.isRequired,
  formik: PropTypes.object.isRequired,
  formikSetField: PropTypes.string.isRequired,
};
