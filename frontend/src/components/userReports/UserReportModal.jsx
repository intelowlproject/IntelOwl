import React from "react";
import {
  Modal,
  ModalHeader,
  ModalBody,
  Form,
  Row,
  Col,
  FormGroup,
  Label,
  Button,
  Input,
  FormFeedback,
} from "reactstrap";
import PropTypes from "prop-types";
import { useFormik, FormikProvider } from "formik";
import axios from "axios";

import { ArrowToggleIcon, addToast } from "@certego/certego-ui";

import { USER_EVENT_ANALYZABLE } from "../../constants/apiURLs";

import {
  Evaluations,
  DataModelKillChainPhases,
} from "../../constants/dataModelConst";
import { ListInput } from "../common/form/ListInput";
import { TagSelectInput } from "../common/form/TagSelectInput";
import {
  DecayProgressionTypes,
  DecayProgressionDescription,
} from "../../constants/userReportsConst";
import { useAuthStore } from "../../stores/useAuthStore";

export function UserReportModal({ analyzables, toggle, isOpen }) {
  console.debug("UserReportModal rendered!");

  const [user] = useAuthStore((state) => [state.user]);
  const [isOpenAdvancedFields, setIsOpenAdvancedFields] = React.useState(false);

  const formik = useFormik({
    initialValues: {
      // base fields
      analyzables: analyzables.map((analyzable) => analyzable.name) || [""],
      evaluation: "",
      kill_chain_phase: "",
      external_references: [""],
      related_threats: [""],
      tags: [],
      malware_family: "",
      // advanced fields
      reliability: 10,
      decay_progression: DecayProgressionTypes.FIXED,
      decay_timedelta_days: 0,
    },
    validate: (values) => {
      console.debug("validate - values");
      console.debug(values);
      const errors = {};

      // check domain wildcard

      // check ip wildcard

      if (!Number.isInteger(values.decay_timedelta_days)) {
        errors.decay_timedelta_days = "The value must be a number.";
      } else if (
        values.decay_timedelta_days !== 0 &&
        values?.decay_progression === DecayProgressionTypes.FIXED
      ) {
        errors.decay_timedelta_days =
          "You can't have a fixed decay progression and days different from 0";
      }

      return errors;
    },
    onSubmit: async () => {
      const editedFields = {};
      Object.entries(formik.values).forEach(([key, value]) => {
        if (
          JSON.stringify(value) !== JSON.stringify(formik.initialValues[key]) &&
          key !== "analyzables"
        ) {
          editedFields[key] = value;
        }
      });

      const reports = [];
      formik.values.analyzables.forEach((analyzable) => {
        reports.push({
          analyzable: { name: analyzable },
          decay_progression: formik.values.decay_progression,
          decay_timedelta_days: formik.values.decay_timedelta_days,
          data_model_content: {
            ...editedFields,
            reliability: formik.values.reliability,
          },
        });
      });

      const requests = reports.map((report) => {
        if (
          analyzables.findIndex(
            (analyzable) =>
              analyzable.id === report.analyzable &&
              analyzable?.user_events
                ?.map((event) => event.user.username)
                .includes(user.username),
          ) !== -1
        ) {
          // edit an existing report
          return axios.patch(`${USER_EVENT_ANALYZABLE}`, report);
        }
        // create a new report
        return axios.post(`${USER_EVENT_ANALYZABLE}`, report);
      });

      Promise.allSettled(requests).then((response) => {
        const failed = [];
        response.forEach((promise, index) => {
          if (promise.status === "rejected")
            failed.push(reports[index].analyzable);
        });
        console.debug(failed);

        if (failed.length === 0) {
          addToast("Report added successfully", null, "success");
          formik.setSubmitting(false);
          formik.resetForm();
          toggle(false);
        } else if (failed.length !== reports.length) {
          addToast(
            `Failed to add reports: ${failed.toString()}`,
            null,
            "warning",
          );
          formik.setFieldValue("analyzables", failed, false);
        } else {
          addToast(
            `Failed to add reports: ${failed.toString()}`,
            null,
            "danger",
          );
          formik.setSubmitting(false);
          formik.resetForm();
          toggle(false);
        }
      });
      return null;
    },
  });

  console.debug("formik", formik.values);

  return (
    <Modal
      id="user-report-modal"
      autoFocus
      centered
      zIndex="1050"
      size="lg"
      backdrop="static"
      labelledBy="User report modal"
      isOpen={isOpen}
      style={{ minWidth: "70%" }}
      toggle={() => toggle(false)}
    >
      <ModalHeader className="mx-2" toggle={() => toggle(false)}>
        <small className="text-info">Add your report</small>
      </ModalHeader>
      <ModalBody className="m-2">
        <FormikProvider value={formik}>
          <Form onSubmit={formik.handleSubmit}>
            <FormGroup>
              <Row>
                <Col md={2} className="d-flex align-items-top mt-2">
                  <Label
                    className="me-2 mb-0 required"
                    for="userReport__analyzables"
                  >
                    Analyzable(s):
                  </Label>
                </Col>
                <Col md={10}>
                  <ListInput
                    id="analyzables"
                    values={formik.values.analyzables}
                    formikSetFieldValue={formik.setFieldValue}
                    placeholder="google.com, 8.8.8.8, https://google.com, 1d5920f4b44b27a802bd77c4f0536f5a, *\.com"
                  />
                </Col>
              </Row>
              {/* <Row>
                <Col className="offset-2 col-9">
                  <small className="fst-italic">
                    Note: if a domain wildcard or a network is entered, the
                    search for existing analyzables that mach will be
                    automatically performed
                  </small>
                </Col>
              </Row> */}
              <hr />
            </FormGroup>
            <FormGroup>
              <Row>
                <Col md={2} className="d-flex align-items-center">
                  <Label
                    className="me-2 mb-0 required"
                    for="userReport__evaluation"
                  >
                    Evaluation:
                  </Label>
                </Col>
                <Col md={8} className="d-flex align-items-center">
                  <Input
                    id="userReport__evaluation"
                    type="select"
                    name="evaluation"
                    value={formik.values.evaluation}
                    onBlur={formik.handleBlur}
                    onChange={formik.handleChange}
                    className="bg-darker border-dark"
                  >
                    <option value="">Select...</option>
                    {[Evaluations.MALICIOUS, Evaluations.TRUSTED]
                      .sort()
                      .map((value) => (
                        <option
                          key={`userReport__evaluation-select-option-${value}`}
                          value={value}
                        >
                          {value.toUpperCase()}
                        </option>
                      ))}
                  </Input>
                </Col>
              </Row>
              <hr />
            </FormGroup>
            <FormGroup>
              <Row>
                <Col md={2} className="d-flex align-items-center">
                  <Label
                    className="me-2 mb-0 required"
                    for="userReport__related_threats"
                  >
                    Comments:
                  </Label>
                </Col>
                <Col md={10}>
                  <ListInput
                    id="related_threats"
                    values={formik.values.related_threats}
                    formikSetFieldValue={formik.setFieldValue}
                  />
                </Col>
              </Row>
              <hr />
            </FormGroup>
            <FormGroup>
              <Row>
                <Col md={2} className="d-flex align-items-center">
                  <Label
                    className="me-2 mb-0"
                    for="userReport__external_references"
                  >
                    External references:
                  </Label>
                </Col>
                <Col md={10}>
                  <ListInput
                    id="external_references"
                    values={formik.values.external_references}
                    formikSetFieldValue={formik.setFieldValue}
                  />
                </Col>
              </Row>
              <hr />
            </FormGroup>
            <FormGroup>
              <Row>
                <Col md={2} className="d-flex align-items-center">
                  <Label
                    className="me-2 mb-0"
                    for="userReport__kill_chain_phase"
                  >
                    Kill chain phase:
                  </Label>
                </Col>
                <Col md={8} className="d-flex align-items-center">
                  <Input
                    id="userReport__kill_chain_phase"
                    type="select"
                    name="kill_chain_phase"
                    value={formik.values.kill_chain_phase}
                    onBlur={formik.handleBlur}
                    onChange={formik.handleChange}
                    className="bg-darker border-dark"
                  >
                    <option value="">Select...</option>
                    {Object.values(DataModelKillChainPhases)
                      .sort()
                      .map((value) => (
                        <option
                          key={`userReport__kill_chain_phase-select-option-${value}`}
                          value={value}
                        >
                          {value.toUpperCase()}
                        </option>
                      ))}
                  </Input>
                </Col>
              </Row>
              <hr />
            </FormGroup>
            <FormGroup row className="d-flex align-items-center">
              <Label sm={2} for="userReport__tags">
                Tags:
              </Label>
              <Col sm={8}>
                <TagSelectInput
                  id="userReport-tagselectinput"
                  selectedTags={formik.values.tags}
                  setSelectedTags={(selectedTags) =>
                    formik.setFieldValue("tags", selectedTags, false)
                  }
                />
              </Col>
            </FormGroup>
            <hr />
            <Row>
              <Button
                size="xs"
                type="button"
                color="primary"
                outline
                className="rounded-1 col-sm-2 text-white py-2 ms-2 mt-2 d-flex-center align-items-center"
                onClick={() => setIsOpenAdvancedFields(!isOpenAdvancedFields)}
              >
                <span className="me-3">Advanced fields</span>
                <ArrowToggleIcon
                  isExpanded={isOpenAdvancedFields}
                  className="text-tertiary bg-white"
                />
              </Button>
            </Row>
            {isOpenAdvancedFields && (
              <>
                <FormGroup className="mt-4">
                  <Row>
                    <Col md={2} className="d-flex align-items-center">
                      <Label
                        className="me-2 mb-0"
                        for="userReport__reliability"
                      >
                        Reliability:
                      </Label>
                    </Col>
                    <Col md={8} className="d-flex-column align-items-center">
                      <Input
                        id="userReport__reliability"
                        type="number"
                        name="reliability"
                        value={formik.values.reliability}
                        onBlur={formik.handleBlur}
                        onChange={formik.handleChange}
                        invalid={
                          !Number.isInteger(formik.values.reliability) ||
                          formik.values.reliability <= 0 ||
                          formik.values.reliability > 10
                        }
                        className="bg-darker border-0"
                      />
                      <FormFeedback>
                        The reliability value must be a number between 1 and 10
                      </FormFeedback>
                    </Col>
                  </Row>
                  <hr />
                </FormGroup>
                <FormGroup className="mt-4">
                  <Row>
                    <Col md={2} className="d-flex align-items-center">
                      <Label
                        className="me-2 mb-0"
                        for="userReport__decay_progression"
                      >
                        Decay type:
                      </Label>
                    </Col>
                    <Col md={8} className="d-flex align-items-center">
                      <Input
                        id="userReport__decay_progression"
                        type="select"
                        name="decay_progression"
                        value={formik.values.decay_progression}
                        onBlur={formik.handleBlur}
                        onChange={formik.handleChange}
                        className="bg-darker border-dark"
                      >
                        <option value="">Select...</option>
                        {Object.entries(DecayProgressionTypes).map(
                          ([decayType, value]) => (
                            <option
                              key={`userReport__decay_progression-select-option-${value}`}
                              value={value}
                            >
                              {decayType.toUpperCase()}
                            </option>
                          ),
                        )}
                      </Input>
                    </Col>
                  </Row>
                  <Row>
                    <small className="col-8 offset-2 mt-2 fst-italic">
                      {
                        DecayProgressionDescription[
                          parseInt(formik.values.decay_progression, 10)
                        ]
                      }
                    </small>
                  </Row>
                  <hr />
                </FormGroup>
                <FormGroup className="mt-4">
                  <Row>
                    <Col md={2} className="d-flex align-items-center">
                      <Label
                        className="me-2 mb-0"
                        for="userReport__decay_timedelta_days"
                      >
                        Decay days:
                      </Label>
                    </Col>
                    <Col md={8} className="d-flex-column align-items-center">
                      <Input
                        id="userReport__decay_timedelta_days"
                        type="number"
                        name="decay_timedelta_days"
                        value={formik.values.decay_timedelta_days}
                        onBlur={formik.handleBlur}
                        onChange={formik.handleChange}
                        invalid={formik.errors?.decay_timedelta_days}
                        className="bg-darker border-0"
                      />
                      <FormFeedback>
                        {formik.errors?.decay_timedelta_days}
                      </FormFeedback>
                    </Col>
                  </Row>
                  <hr />
                </FormGroup>
              </>
            )}
            <FormGroup className="d-flex justify-content-end align-items-center mt-3">
              <Button
                id="plugin-config"
                type="submit"
                color="primary"
                size="xl"
                outline
                className="mx-2 mt-2 text-white"
                /* dirty return True if values are different then default
                  we cannot run the validation on mount or we get an infinite loop.
                */
                disabled={
                  !formik.isValid || formik.isSubmitting || !formik.dirty
                }
              >
                Save
              </Button>
            </FormGroup>
          </Form>
        </FormikProvider>
      </ModalBody>
    </Modal>
  );
}

UserReportModal.propTypes = {
  analyzables: PropTypes.arrayOf(Object),
  toggle: PropTypes.func.isRequired,
  isOpen: PropTypes.bool.isRequired,
};

UserReportModal.defaultProps = {
  analyzables: [""],
};
