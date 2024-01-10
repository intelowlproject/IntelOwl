import React from "react";
import PropTypes from "prop-types";
import { Modal, ModalHeader, ModalBody, Button, Input } from "reactstrap";

import { ContentSection } from "@certego/certego-ui";
import {
  observableValidators,
  sanitizeObservable,
} from "./observableValidators";

// components
export function MultipleObservablesModal(props) {
  const { isOpen, toggle, formik, ...rest } = props;
  const [extractedObservables, setExtractedObservables] = React.useState({});
  const [textAreaInput, setTextAreaInput] = React.useState("");

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
      if (validationValue !== null)
        observables[validationValue.classification].push(
          validationValue.observable,
        );
    });

    // remove duplicates
    Object.keys(observables).forEach((key) => {
      observables[key] = [...new Set(observables[key])];
    });

    console.debug("MultipleObservablesModal - observables:");
    console.debug(observables);
    setExtractedObservables(observables);

    const textHighlightColor = (text) => {
      if (observables.domain.includes(text)) return "bg-dark text-primary";
      if (observables.ip.includes(text)) return "bg-dark text-warning";
      if (observables.hash.includes(text)) return "bg-dark text-success";
      if (observables.url.includes(text)) return "bg-dark text-danger";
      return null;
    };

    setTextAreaInput(
      inputText.split(/\n/).map((line) => (
        <>
          <span className="d-inline-flex flex-wrap">
            {line.split(/\s/).map((part) => (
              <>
                <span
                  className={textHighlightColor(sanitizeObservable(part))}
                  key={`highlightArea__${part}`}
                >
                  {part}
                </span>
                &nbsp;
              </>
            ))}
          </span>
          <br />
        </>
      )),
    );
  };

  const saveAndCloseModal = () => {
    const observableNames = Object.values(extractedObservables).flat();
    formik.setFieldValue("observable_names", observableNames, false);
    toggle();
  };

  return (
    <Modal
      autoFocus
      zIndex="1050"
      size="xl"
      isOpen={isOpen}
      toggle={toggle}
      keyboard={false}
      scrollable
      backdrop="static"
      labelledBy="Load Multiple Observables"
      style={{ minWidth: "95%" }}
      {...rest}
    >
      <ModalHeader className="bg-tertiary" toggle={toggle}>
        Load Multiple Observables
      </ModalHeader>
      <ModalBody
        className="d-flex-column bg-body"
        id="load_multiple_observables-ModalBody"
      >
        <div className="d-flex-start-start bg-body">
          <ContentSection
            className="bg-darker"
            id="load_multiple_observables-section"
            style={{ width: "40%" }}
          >
            <small className="text-muted mb-2">
              Enter any text to extract observables for further lookup.
            </small>
            <Input
              id="load_multiple_observables-textArea"
              name="textArea"
              type="textarea"
              onChange={(e) => extractObservables(e.target.value)}
              style={{ minHeight: "600px", overflowY: "auto" }}
              className="my-2 mt-3"
            />
          </ContentSection>
          {/* lateral menu with the extracted observables */}
          <ContentSection className="ms-2 bg-darker" style={{ width: "60%" }}>
            <h5 className="text-accent">Extracted observables</h5>
            <div
              className="d-flex-start-start"
              style={{ maxHeight: "660px", overflowY: "auto" }}
            >
              <div
                id="load_multiple_observables-highlightArea"
                style={{ width: "65%", height: "600px", overflowY: "auto" }}
                className="form-control my-2"
              >
                {textAreaInput}
              </div>
              <div
                className="ps-4"
                style={{ width: "35%", height: "600px", overflowY: "auto" }}
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

MultipleObservablesModal.propTypes = {
  isOpen: PropTypes.bool.isRequired,
  toggle: PropTypes.func.isRequired,
  formik: PropTypes.object.isRequired,
};
