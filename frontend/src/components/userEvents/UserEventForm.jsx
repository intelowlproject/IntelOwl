import React from "react";
import {
  Form,
  Row,
  Col,
  FormGroup,
  Label,
  Button,
  Input,
  FormFeedback,
  Badge,
  Nav,
  NavItem,
  NavLink,
  TabContent,
  TabPane,
  ButtonGroup,
} from "reactstrap";
import PropTypes from "prop-types";
import { useFormik, FormikProvider, FieldArray } from "formik";
import axios from "axios";
import ReactSelect from "react-select";
import { useNavigate } from "react-router-dom";

import {
  ArrowToggleIcon,
  MultiSelectCreatableInput,
  addToast,
  selectStyles,
} from "@certego/certego-ui";

import {
  DataModelEvaluations,
  DataModelKillChainPhases,
  DataModelTags,
  DataModelEvaluationIcons,
} from "../../constants/dataModelConst";
import { ListInput } from "../common/form/ListInput";
import {
  DecayProgressionTypes,
  DecayProgressionDescription,
  UserEventTypes,
  userEventTypesToApiMapping,
  evaluationOptions,
} from "../../constants/userEventsConst";
import { TagsColors, EvaluationColors } from "../../constants/colorConst";
import {
  killChainPhaseOptionLabel,
  BasicEvaluationWarning,
} from "./userEventFormUtils";
import { AnalyzableInputField } from "./AnalyzableInputField";
import { UserExistingEvaluationsSection } from "./UserExistingEvaluationsSection";
import { getIcon } from "../common/icon/icons";
import { areYouSureConfirmDialog } from "../common/areYouSureConfirmDialog";

const EXCLUDE_EVALUATION_RELIABILITY = "8";

export function UserEventForm({ initialFormValues, toggle, onSubmitCallback }) {
  console.debug("UserEventForm rendered!");

  // router navigation
  const navigate = useNavigate();

  const [isOpenAdvancedFields, setIsOpenAdvancedFields] = React.useState(false);
  const [inputTypes, setInputTypes] = React.useState({});
  const [userExistingEvents, setUserExistingEvents] = React.useState({});
  const [manualEvaluationTab, setManualEvaluationTab] = React.useState(
    initialFormValues.basic_evaluation === null,
  );
  const [excludeEvaluation, setExcludeEvaluation] = React.useState(false);

  const formik = useFormik({
    initialValues: initialFormValues,
    validateOnChange: false,
    validateOnBlur: true,
    validate: (values) => {
      console.debug("validate - values");
      console.debug(values);
      const errors = {};
      if (values.analyzables[0] === "") {
        errors["analyzables-0"] = "Artifact is required";
      }
      // control used to report the errors produced by requests performed in previous rendering
      values.analyzables.forEach((analyzable, index) => {
        if (
          Object.keys(inputTypes).includes(analyzable) &&
          inputTypes[analyzable].error !== null
        )
          errors[`analyzables-${index}`] = inputTypes[analyzable].error;
      });
      if (values.reason === "") {
        errors.reason = "Reason is required";
      }
      if (!Number.isInteger(values.decay_timedelta_days)) {
        errors.decay_timedelta_days = "The value must be a number.";
      }
      if (
        values.decay_timedelta_days !== 0 &&
        values.decay_progression === DecayProgressionTypes.FIXED
      ) {
        errors.decay_timedelta_days =
          "You can't have a fixed decay progression and days different from 0";
      }
      console.debug("errors", errors);
      return errors;
    },
    onSubmit: async () => {
      let exists = false;
      formik.values.analyzables.forEach((analyzable) => {
        if (Object.keys(userExistingEvents).includes(analyzable)) exists = true;
      });
      if (exists) {
        const text = (
          <div>
            <span>
              You are evaluating one or more indicators that you have previously
              evaluated. All fields entered in the form (including empty ones)
              will overwrite existing ones.
            </span>
            <ul className="text-start mt-4">
              {Object.entries(userExistingEvents).map(([analyzable, event]) => {
                if (formik.values.analyzables.includes(analyzable)) {
                  return <li key={`event__${event.id}`}>{analyzable}</li>;
                }
                return null;
              })}
            </ul>
          </div>
        );
        const sure = await areYouSureConfirmDialog(text);
        if (!sure) return null;
      }

      const evaluation = {
        reason: formik.values.reason,
        decay_progression: formik.values.decay_progression,
        decay_timedelta_days: formik.values.decay_timedelta_days,
        data_model_content: {
          evaluation: excludeEvaluation ? null : formik.values.evaluation,
          reliability: excludeEvaluation
            ? EXCLUDE_EVALUATION_RELIABILITY
            : formik.values.reliability,
          external_references:
            formik.values.external_references[0] !== ""
              ? formik.values.external_references
              : [],
          related_threats:
            formik.values.related_threats[0] !== ""
              ? formik.values.related_threats
              : [],
          malware_family: formik.values.malware_family,
          kill_chain_phase:
            formik.values.kill_chain_phase !== ""
              ? formik.values.kill_chain_phase.value
              : "",
          tags: formik.values.tags.length
            ? formik.values.tags.map((tag) => tag.value)
            : [],
        },
      };

      const failed = [];
      Promise.allSettled(
        formik.values.analyzables.map((analyzable) => {
          if (inputTypes[analyzable].type === UserEventTypes.IP_WILDCARD)
            evaluation.network = analyzable;
          else if (
            inputTypes[analyzable].type === UserEventTypes.DOMAIN_WILDCARD
          )
            evaluation.query = analyzable;
          else evaluation.analyzable = { name: analyzable };

          if (userExistingEvents[analyzable]?.event) {
            // edit an existing evaluation
            return axios.patch(
              `${userEventTypesToApiMapping[inputTypes[analyzable].type]}/${
                userExistingEvents[analyzable].event
              }`,
              evaluation,
            );
          }
          // create a new evaluation
          return axios.post(
            `${userEventTypesToApiMapping[inputTypes[analyzable].type]}`,
            evaluation,
          );
        }),
      ).then((response) => {
        response.forEach((promise, index) => {
          if (promise.status === "rejected") {
            failed.push(formik.values.analyzables[index]);
            addToast(
              `Failed to add evaluation for: ${formik.values.analyzables[index]}`,
              promise?.reason.parsedMsg,
              "danger",
            );
          } else {
            addToast(
              `Evaluation added successfully for: ${formik.values.analyzables[index]}`,
              null,
              "success",
            );
          }
        });

        if (
          failed.length === 0 &&
          formik.values.analyzables.length === 1 &&
          userExistingEvents[formik.values.analyzables[0]]?.id !== undefined &&
          inputTypes[formik.values.analyzables[0]].type ===
            UserEventTypes.ANALYZABLE
        ) {
          // casa A: single artifact with existing event (no wildcard)
          setTimeout(
            () =>
              navigate(
                `/artifacts/${
                  userExistingEvents[formik.values.analyzables[0]].id
                }`,
              ),
            1000,
          );
        } else if (failed.length === 0) {
          // casa B: no errors
          const submittedAnalyzables = [...formik.values.analyzables];
          formik.setSubmitting(false);
          formik.resetForm();
          if (onSubmitCallback) {
            onSubmitCallback(submittedAnalyzables);
          }
          toggle(false);
        } else {
          // casa C: errors
          formik.setFieldValue("analyzables", failed, false);
        }
      });
      return null;
    },
  });

  console.debug("UserEventForm - formik values", formik.values);
  console.debug("UserEventForm - inputTypes", inputTypes);
  console.debug("UserEventForm - userExistingEvents", userExistingEvents);

  const basicEvaluationOnChange = (basicEval) => {
    formik.setValues(
      {
        ...formik.values,
        basic_evaluation: basicEval,
        evaluation: evaluationOptions[basicEval].evaluation,
        reliability: evaluationOptions[basicEval].reliability,
      },
      true, // second set must trigger the validate or update evaluation with pre-populated form won't work
    );
  };

  return (
    <FormikProvider value={formik}>
      <Form onSubmit={formik.handleSubmit}>
        <div className="d-flex">
          <div style={{ width: "75%" }} className="me-3">
            <FormGroup>
              <Row>
                <Col md={2} className="d-flex align-items-top mt-2">
                  <Label
                    className="me-2 mb-0 required"
                    for="userEvent__analyzables"
                  >
                    Artifact(s) or IP/Domain wildcard:
                  </Label>
                </Col>
                <Col md={10}>
                  <FieldArray
                    name="analyzables"
                    validateOnChange={false}
                    render={(arrayHelpers) => (
                      <FormGroup row>
                        <div style={{ maxHeight: "40vh", overflowY: "scroll" }}>
                          {formik.values.analyzables &&
                          formik.values.analyzables.length > 0
                            ? formik.values.analyzables.map((value, index) => (
                                <AnalyzableInputField
                                  index={index}
                                  arrayHelpers={arrayHelpers}
                                  initialValue={value}
                                  formik={formik}
                                  setInputTypes={setInputTypes}
                                />
                              ))
                            : null}
                        </div>
                      </FormGroup>
                    )}
                  />
                </Col>
              </Row>
            </FormGroup>
            <hr />
            <FormGroup>
              <Row>
                <Col md={2} className="d-flex flex-column align-items-start">
                  <Label
                    className="me-2 mb-0 required py-3"
                    for="userEvent__evaluation"
                  >
                    Evaluation:
                  </Label>
                  <FormGroup check className="d-flex align-items-center m-0">
                    <Input
                      id="exclude-evaluation-flag"
                      type="checkbox"
                      defaultChecked={false}
                      className="mt-0 me-1"
                      onChange={(event) =>
                        setExcludeEvaluation(event.target.checked)
                      }
                    />
                    <Label check>
                      <small>Exclude evaluation</small>
                    </Label>
                  </FormGroup>
                </Col>
                <Col>
                  <Nav tabs className="mt-2">
                    <NavItem>
                      <NavLink
                        className={
                          manualEvaluationTab ? "" : "active text-info fw-bold"
                        }
                        style={{ border: "1px solid #001d24" }}
                        onClick={() => setManualEvaluationTab(false)}
                        id="userEvent__evaluation-basic"
                      >
                        Basic
                      </NavLink>
                    </NavItem>
                    <NavItem>
                      <NavLink
                        className={
                          manualEvaluationTab ? "active text-info fw-bold" : ""
                        }
                        style={{ border: "1px solid #001d24" }}
                        onClick={() => setManualEvaluationTab(true)}
                        id="userEvent__evaluation-manual"
                      >
                        Manual
                      </NavLink>
                    </NavItem>
                  </Nav>
                  <TabContent
                    activeTab={manualEvaluationTab ? "manual" : "basic"}
                    className="p-2 mt-2"
                  >
                    <TabPane tabId="basic">
                      <ButtonGroup className="gap-1 mb-2">
                        {Object.values(evaluationOptions).map(
                          (value, index) => (
                            <Button
                              color={EvaluationColors[value.evaluation]}
                              outline
                              onClick={() =>
                                basicEvaluationOnChange(index.toString())
                              }
                              active={
                                formik.values.basic_evaluation ===
                                index.toString()
                              }
                              className="text-light"
                              disabled={excludeEvaluation}
                            >
                              {getIcon(
                                DataModelEvaluationIcons[value.evaluation],
                              )}
                              &nbsp;{value.label}
                            </Button>
                          ),
                        )}
                      </ButtonGroup>
                      <BasicEvaluationWarning
                        evaluation={formik.values.evaluation}
                        reliability={formik.values.reliability}
                        basicEvaluation={formik.values.basic_evaluation}
                      />
                    </TabPane>
                    <TabPane tabId="manual">
                      <div className="d-flex row">
                        <ButtonGroup className="gap-1 mb-2 col-4">
                          {[
                            DataModelEvaluations.MALICIOUS,
                            DataModelEvaluations.TRUSTED,
                          ].map((value) => (
                            <Button
                              color={EvaluationColors[value]}
                              outline
                              onClick={() =>
                                formik.setFieldValue("evaluation", value, false)
                              }
                              active={
                                formik.values.evaluation.toString() === value
                              }
                              className="text-light"
                              disabled={excludeEvaluation}
                            >
                              {getIcon(DataModelEvaluationIcons[value])}&nbsp;
                              {value}
                            </Button>
                          ))}
                        </ButtonGroup>
                        <FormGroup className="d-flex align-items-center col-4 ms-4">
                          <Label
                            className="me-4 mb-0"
                            for="userEvent__reliability-advanced"
                          >
                            Reliability:&nbsp;{formik.values.reliability}
                          </Label>
                          <Input
                            id="userEvent__reliability-advanced"
                            type="range"
                            name="reliability"
                            min="0"
                            max="10"
                            step="1"
                            value={formik.values.reliability}
                            onBlur={formik.handleBlur}
                            onChange={(event) => {
                              formik.setFieldValue(
                                "reliability",
                                event.target.value,
                                false,
                              );
                              formik.setFieldValue(
                                "basic_evaluation",
                                null,
                                false,
                              );
                            }}
                            className="color-range-slider ms-2"
                            style={{
                              "--slider-fill-color":
                                formik.values.evaluation.toString() ===
                                DataModelEvaluations.MALICIOUS
                                  ? "#ee4544"
                                  : "#02cc56",
                              "--fill-percentage": `${
                                formik.values.reliability * 10
                              }%`,
                            }}
                            disabled={excludeEvaluation}
                          />
                        </FormGroup>
                      </div>
                      <small>
                        {formik.values.evaluation.toString() ===
                        DataModelEvaluations.MALICIOUS
                          ? "An artifact associated with malicious behavior. Using the reliability slider, you can adjust the level of confidence that the artifact has that evaluation."
                          : "An artifact with no evidence of malicious activity. Using the reliability slider, you can adjust the level of confidence that the artifact has that evaluation."}
                      </small>
                    </TabPane>
                  </TabContent>
                </Col>
              </Row>
            </FormGroup>
            <hr />
            <FormGroup>
              <Row>
                <Col md={2} className="d-flex align-items-center">
                  <Label className="me-2 mb-0 required" for="userEvent__reason">
                    Reason:
                  </Label>
                </Col>
                <Col md={8}>
                  <Input
                    id="reason"
                    name="reason"
                    type="textarea"
                    className="input-dark"
                    value={formik.values.reason}
                    onChange={formik.handleChange}
                    onBlur={formik.handleBlur}
                    invalid={formik.errors.reason && formik.touched.reason}
                  />
                  {formik.errors.reason && formik.touched.reason && (
                    <span className="text-danger">{formik.errors.reason}</span>
                  )}
                </Col>
              </Row>
            </FormGroup>
            <hr />
            <FormGroup>
              <Row>
                <Col md={2} className="d-flex align-items-center">
                  <Label className="me-2 mb-0" for="userEvent__malware_family">
                    Malware family:
                  </Label>
                </Col>
                <Col md={8}>
                  <Input
                    id="malware_family"
                    name="malware_family"
                    type="text"
                    className="input-dark"
                    value={formik.values.malware_family}
                    onChange={formik.handleChange}
                    onBlur={formik.handleBlur}
                  />
                </Col>
              </Row>
            </FormGroup>
            <hr />
            <FormGroup>
              <Row>
                <Col md={2} className="d-flex align-items-center">
                  <Label className="me-2 mb-0" for="userEvent__related_threats">
                    Related Artifacts:
                  </Label>
                </Col>
                <Col md={10}>
                  <ListInput
                    id="related_threats"
                    values={formik.values.related_threats}
                    formikSetFieldValue={formik.setFieldValue}
                    formikHandlerBlur={formik.handleBlur}
                  />
                </Col>
              </Row>
            </FormGroup>
            <hr />
            <FormGroup>
              <Row>
                <Col md={2} className="d-flex align-items-center">
                  <Label
                    className="me-2 mb-0"
                    for="userEvent__external_references"
                  >
                    External references:
                  </Label>
                </Col>
                <Col md={10}>
                  <ListInput
                    id="external_references"
                    values={formik.values.external_references}
                    formikSetFieldValue={formik.setFieldValue}
                    formikHandlerBlur={formik.handleBlur}
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
                    for="userEvent__kill_chain_phase"
                  >
                    Kill chain phase:
                  </Label>
                </Col>
                <Col sm={8}>
                  <ReactSelect
                    isClearable
                    options={Object.values(DataModelKillChainPhases).map(
                      (killChainPhase) => ({
                        value: killChainPhase,
                        label: killChainPhaseOptionLabel(killChainPhase),
                      }),
                    )}
                    styles={selectStyles}
                    value={formik.values.kill_chain_phase}
                    onChange={(killChainPhase) =>
                      formik.setFieldValue(
                        "kill_chain_phase",
                        killChainPhase,
                        false,
                      )
                    }
                  />
                </Col>
              </Row>
              <hr />
            </FormGroup>
            <FormGroup row className="d-flex align-items-center">
              <Label sm={2} for="userEvent__tags">
                Tags:
              </Label>
              <Col sm={8}>
                <MultiSelectCreatableInput
                  id="scanform-tagsselectinput"
                  options={Object.values(DataModelTags).map((tag) => ({
                    value: tag,
                    label: <Badge color={TagsColors[tag]}>{tag}</Badge>,
                  }))}
                  value={formik.values.tags}
                  styles={selectStyles}
                  onChange={(tag) => formik.setFieldValue("tags", tag, false)}
                  isClearable
                />
              </Col>
            </FormGroup>
            <hr />
          </div>
          <div style={{ width: "25%" }} className="bg-tertiary mb-3">
            <UserExistingEvaluationsSection
              inputData={inputTypes}
              analyzables={formik.values.analyzables}
              setUserExistingEvents={setUserExistingEvents}
              formik={formik}
            />
          </div>
        </div>
        {/* ADVANCED SECTION */}
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
                    for="userEvent__decay_progression"
                  >
                    Decay type:
                  </Label>
                </Col>
                <Col md={8} className="d-flex align-items-center">
                  <Input
                    id="userEvent__decay_progression"
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
                          key={`userEvent__decay_progression-select-option-${value}`}
                          value={value}
                          className="d-flex flex-column"
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
                    for="userEvent__decay_timedelta_days"
                  >
                    Decay days:
                  </Label>
                </Col>
                <Col md={8} className="d-flex-column align-items-center">
                  <Input
                    id="userEvent__decay_timedelta_days"
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
            id="user-event"
            type="submit"
            color="primary"
            size="xl"
            outline
            className="mx-2 mt-2 text-white"
            disabled={!formik.dirty || !formik.isValid || formik.isSubmitting}
          >
            Save
          </Button>
        </FormGroup>
      </Form>
    </FormikProvider>
  );
}

UserEventForm.propTypes = {
  initialFormValues: PropTypes.object.isRequired,
  toggle: PropTypes.func.isRequired,
  onSubmitCallback: PropTypes.func,
};

UserEventForm.defaultProps = {
  onSubmitCallback: undefined,
};
