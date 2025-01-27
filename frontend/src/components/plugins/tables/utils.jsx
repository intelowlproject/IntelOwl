import React from "react";
import PropTypes from "prop-types";
import { Modal, ModalHeader, ModalBody, UncontrolledTooltip } from "reactstrap";
import { VscJson } from "react-icons/vsc";
import { MdInfoOutline } from "react-icons/md";
import { Link } from "react-router-dom";

import { IconButton, CustomJsonInput } from "@certego/certego-ui";

export function MappingDataModel({ data, type, pythonModule }) {
  // state
  const [showModal, setShowModal] = React.useState(false);
  const pythonModuleName = pythonModule.split(".")[0];

  return (
    <div className="d-flex flex-column align-items-center p-1">
      <IconButton
        id={`mapping-data-model__${pythonModuleName}`}
        color="info"
        size="sm"
        Icon={VscJson}
        title="View data model mapping"
        onClick={() => setShowModal(!showModal)}
        titlePlacement="top"
      />
      {showModal && (
        <Modal
          id="mapping-data-model-modal"
          autoFocus
          centered
          zIndex="1050"
          size="lg"
          keyboard={false}
          backdrop="static"
          labelledBy="Data model modal"
          isOpen={showModal}
          style={{ minWidth: "50%" }}
        >
          <ModalHeader className="mx-2" toggle={() => setShowModal(false)}>
            <small className="text-info">
              Data model mapping
              <MdInfoOutline
                id="dataModelMapping_infoicon"
                fontSize="16"
                className="ms-2"
              />
              <UncontrolledTooltip
                trigger="hover"
                target="dataModelMapping_infoicon"
                placement="right"
                fade={false}
                autohide={false}
                innerClassName="p-2 text-start text-nowrap md-fit-content"
              >
                The main functionality of a `DataModel` is to model an
                `Analyzer` result to a set of prearranged keys, allowing users
                to easily search, evaluate and use the analyzer result.
                <br />
                For more info check the{" "}
                <Link
                  to="https://intelowlproject.github.io/docs/IntelOwl/usage/#DataModels"
                  target="_blank"
                >
                  official doc.
                </Link>
              </UncontrolledTooltip>
            </small>
          </ModalHeader>
          <ModalBody className="d-flex flex-column mx-2">
            <small>
              The <strong className="text-info">keys </strong>
              represent the path from which retrieve the value in the analyzer
              report and the <strong className="text-info">value</strong> the
              path of the data model.
            </small>
            <small>
              For more info check the{" "}
              <Link
                to={`https://github.com/intelowlproject/IntelOwl/blob/master/api_app/analyzers_manager/${type}_analyzers/${pythonModuleName}.py`}
                target="_blank"
              >
                analyzer&apos;s source code.
              </Link>
            </small>
            <div className="my-2 d-flex justify-content-center">
              <CustomJsonInput
                id="data_model_mapping_json"
                placeholder={data}
                viewOnly
                confirmGood={false}
              />
            </div>
          </ModalBody>
        </Modal>
      )}
    </div>
  );
}

MappingDataModel.propTypes = {
  type: PropTypes.string.isRequired,
  data: PropTypes.object.isRequired,
  pythonModule: PropTypes.string.isRequired,
};
