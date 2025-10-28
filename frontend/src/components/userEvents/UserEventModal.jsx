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
  UncontrolledTooltip,
  Badge,
  Nav,
  NavItem,
  NavLink,
  TabContent,
  TabPane,
} from "reactstrap";
import PropTypes from "prop-types";
import { useFormik, FormikProvider, FieldArray } from "formik";
import axios from "axios";
import { BsFillTrashFill, BsFillPlusCircleFill } from "react-icons/bs";
import { MdInfoOutline } from "react-icons/md";
import { IoMdWarning } from "react-icons/io";

import {
  ArrowToggleIcon,
  MultiSelectCreatableInput,
  addToast,
  selectStyles,
  useDebounceInput,
} from "@certego/certego-ui";

import ReactSelect from "react-select";
import {
  USER_EVENT_ANALYZABLE,
  USER_EVENT_IP_WILDCARD,
  USER_EVENT_DOMAIN_WILDCARD,
} from "../../constants/apiURLs";

import {
  DataModelEvaluations,
  DataModelKillChainPhases,
  DataModelKillChainPhasesDescriptions,
  DataModelTags,
} from "../../constants/dataModelConst";
import { ListInput } from "../common/form/ListInput";
import {
  DecayProgressionTypes,
  DecayProgressionDescription,
  UserEventTypes,
  userEventTypesToApiMapping,
} from "../../constants/userEventsConst";
import { useAuthStore } from "../../stores/useAuthStore";
import {
  IP_REGEX,
  DOMAIN_REGEX,
  URL_REGEX,
  HASH_REGEX,
} from "../../constants/regexConst";
import { TagsColors } from "../../constants/colorConst";
import { EvaluationBadge } from "../common/engineBadges";

const RELIABILITY_CONFIRMED_MALICIOUS = 10;
const RELIABILITY_MALICIOUS = 7;
const RELIABILITY_CURRENTLY_TRUSTED = 8;
const RELIABILITY_TRUSTED = 10;

const evaluationOptions = [
  {
    id: 0,
    evaluation: DataModelEvaluations.MALICIOUS,
    label: "Confirmed malicious",
    reliability: RELIABILITY_CONFIRMED_MALICIOUS,
    description:
      "Artifact that has been verified as actively involved in malicious activity (phishing site, download sample, c2, ...).",
  },
  {
    id: 1,
    evaluation: DataModelEvaluations.MALICIOUS,
    label: "Malicious",
    reliability: RELIABILITY_MALICIOUS,
    description:
      "Artifact that is associated with potentially malicious operations (connectivity check, etc.).",
  },
  {
    id: 2,
    evaluation: DataModelEvaluations.TRUSTED,
    label: "Currently trusted",
    reliability: RELIABILITY_CURRENTLY_TRUSTED,
    description:
      "Artifact that shows no sign of malicious behavior at present, though its status could change over time.",
  },
  {
    id: 3,
    evaluation: DataModelEvaluations.TRUSTED,
    label: "Trusted",
    reliability: RELIABILITY_TRUSTED,
    description:
      "A well-known and trusted artifact associated with a widely used legitimate service (es: google.com, 8.8.8.8, etc...)",
  },
];

export function UserEventModal({ analyzables, toggle, isOpen }) {
  console.debug("UserEventModal rendered!");

  const [user] = useAuthStore((state) => [state.user]);
  const [isOpenAdvancedFields, setIsOpenAdvancedFields] = React.useState(false);

  const [inputValue, setInputValue] = React.useState("");
  const [wildcard, setWildcard] = React.useState("");
  const [inputState, setInputState] = React.useState({});
  const [wildcardInputError, setWildcardInputError] = React.useState(null);
  const [advancedEvaluationTab, setAdvancedEvaluationTab] =
    React.useState(false);

  const formik = useFormik({
    initialValues: {
      // base data model fields
      analyzables: analyzables.map((analyzable) => analyzable?.name || ""),
      basic_evaluation: "0",
      kill_chain_phase: "",
      external_references: [""],
      related_threats: [""],
      tags: [],
      malware_family: "",
      // advanced fields
      evaluation: DataModelEvaluations.MALICIOUS,
      reliability: 10,
      decay_progression: DecayProgressionTypes.LINEAR,
      decay_timedelta_days: 120,
    },
    validate: (values) => {
      console.debug("validate - values");
      console.debug(values);
      const errors = {};
      if (values.analyzables[0] === "") {
        errors["analyzables-0"] = "Artifact is required";
      }
      // control used to report the errors produced by requests performed in previous rendering
      values.analyzables.forEach((analyzable, index) => {
        if (wildcardInputError) {
          if (
            Object.keys(wildcardInputError).includes(analyzable) &&
            wildcardInputError[analyzable] !== null
          )
            errors[`analyzables-${index}`] = wildcardInputError[analyzable];
        }
      });
      if (values.related_threats[0] === "") {
        errors["related_threats-0"] = "Reason is required";
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
    validateOnMount: true,
    onSubmit: async () => {
      const editedFields = {};
      delete formik.values.basic_evaluation; // not needed in the request
      Object.entries(formik.values).forEach(([key, value]) => {
        if (
          /* order matters! kill chain also HTML and cannot be converted into JSON
          check before the fields and then check if they are different from the default values
          */
          !["analyzables", "kill_chain_phase", "tags"].includes(key) &&
          JSON.stringify(value) !== JSON.stringify(formik.initialValues[key])
        ) {
          editedFields[key] = value;
        }
        // special cases for kill chain: it has a key with html as value
        if (key === "kill_chain_phase" && value !== "") {
          editedFields.kill_chain_phase = value.value;
        }
        if (key === "tags" && value.length) {
          editedFields.tags = value.map((tag) => tag.value);
        }
      });
      console.debug("editedFields", editedFields);
      const evaluation = {
        decay_progression: formik.values.decay_progression,
        decay_timedelta_days: formik.values.decay_timedelta_days,
        data_model_content: {
          ...editedFields,
          evaluation: formik.values.evaluation,
          reliability: formik.values.reliability,
        },
      };
      console.debug("evaluation", evaluation);

      const failed = [];
      Promise.allSettled(
        formik.values.analyzables.map((analyzable) => {
          if (inputState[analyzable].type === UserEventTypes.IP_WILDCARD)
            evaluation.network = analyzable;
          else if (
            inputState[analyzable].type === UserEventTypes.DOMAIN_WILDCARD
          )
            evaluation.query = analyzable;
          else evaluation.analyzable = { name: analyzable };

          if (inputState[analyzable]?.eventId) {
            // edit an existing evaluation
            return axios.patch(
              `${userEventTypesToApiMapping[inputState[analyzable].type]}/${
                inputState[analyzable].eventId
              }`,
              evaluation,
            );
          }
          // create a new evaluation
          return axios.post(
            `${userEventTypesToApiMapping[inputState[analyzable].type]}`,
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
        if (failed.length === 0) {
          formik.setSubmitting(false);
          formik.resetForm();
          toggle(false);
        } else {
          formik.setFieldValue("analyzables", failed, false);
        }
      });
      return null;
    },
  });

  React.useEffect(() => {
    // this useEffect populate initial state in case the model is accessed from previously searched analyzables
    const obj = {};
    analyzables.forEach((analyzable) => {
      if (analyzable.name !== "") {
        obj[analyzable.name] = {
          type: UserEventTypes.ANALYZABLE,
          eventId: analyzable.id,
        };
      }
    });
    setInputState({ ...inputState, ...obj });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [analyzables]);

  useDebounceInput(inputValue, 1000, setWildcard);

  React.useEffect(() => {
    // this useEffect detect the type of user event while typing
    if (wildcard !== "") {
      // check ip wildcard
      if (
        IP_REGEX.test(wildcard.split(/[/]/)[0]) &&
        wildcard.split(/[/]/).length === 2
      ) {
        // validate ip wildcard
        axios
          .put(`${USER_EVENT_IP_WILDCARD}/validate`, { network: wildcard })
          .then((response) => {
            setWildcardInputError({ [wildcard]: null });
            // check if an ip wildcard event already exists for the same user
            axios
              .get(
                `${USER_EVENT_IP_WILDCARD}?username=${user.username}&network=${wildcard}`,
              )
              .then((resp) => {
                setInputState({
                  ...inputState,
                  [wildcard]: {
                    type: UserEventTypes.IP_WILDCARD,
                    matches: response.data,
                    eventId:
                      resp.data.count !== 0 ? resp.data.results[0].id : null,
                  },
                });
              });
          })
          .catch((error) => {
            setWildcardInputError({
              [wildcard]: error?.response?.data?.errors?.detail,
            });
          });
      } else if (
        // check if the input is not a known observable
        !DOMAIN_REGEX.test(wildcard) &&
        !IP_REGEX.test(wildcard) &&
        !URL_REGEX.test(wildcard) &&
        !HASH_REGEX.test(wildcard) &&
        /\*/.test(wildcard) // check if the character * is in the string
      ) {
        // check domain wildcard
        axios
          .put(`${USER_EVENT_DOMAIN_WILDCARD}/validate`, { query: wildcard })
          .then((response) => {
            setWildcardInputError({ [wildcard]: null });
            // check if a domain wildcard event already exists for the same user
            axios
              .get(
                `${USER_EVENT_DOMAIN_WILDCARD}?username=${user.username}&query=${wildcard}`,
              )
              .then((resp) => {
                setInputState({
                  ...inputState,
                  [wildcard]: {
                    type: UserEventTypes.DOMAIN_WILDCARD,
                    matches: response.data,
                    eventId:
                      resp.data.count !== 0 ? resp.data.results[0].id : null,
                  },
                });
              });
          })
          .catch((error) => {
            setWildcardInputError({
              [wildcard]: error?.response?.data?.errors?.detail,
            });
          });
      } else {
        // input is not a wildcard
        setWildcardInputError({ [wildcard]: null });
        // check if an analyzable event already exists for the same user
        axios
          .get(
            `${USER_EVENT_ANALYZABLE}?username=${user.username}&analyzable_name=${wildcard}`,
          )
          .then((resp) => {
            setInputState({
              ...inputState,
              [wildcard]: {
                type: UserEventTypes.ANALYZABLE,
                eventId: resp.data.count !== 0 ? resp.data.results[0].id : null,
              },
            });
          });
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [wildcard]);

  console.debug("userEventModal - formik values", formik.values);
  console.debug("userEventModal - inputState", inputState);

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
      style={{ minWidth: "70%" }}
      toggle={() => {
        formik.resetForm();
        toggle(false);
      }}
    >
      <ModalHeader
        className="mx-2"
        toggle={() => {
          formik.resetForm();
          toggle(false);
        }}
      >
        <small className="text-info">Add your evaluation</small>
      </ModalHeader>
      <ModalBody className="m-2">
        <FormikProvider value={formik}>
          <Form onSubmit={formik.handleSubmit}>
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
                    render={(arrayHelpers) => (
                      <FormGroup row>
                        <div style={{ maxHeight: "40vh", overflowY: "scroll" }}>
                          {formik.values.analyzables &&
                          formik.values.analyzables.length > 0
                            ? formik.values.analyzables.map((value, index) => (
                                <div>
                                  <div
                                    className="py-2 d-flex"
                                    key={`analyzables-${index + 0}`}
                                  >
                                    <Col sm={10} className="pe-3">
                                      <Input
                                        type="text"
                                        id={`analyzables-${index}`}
                                        name={`analyzables-${index}`}
                                        placeholder="google.com, 8.8.8.8, https://google.com, 1d5920f4b44b27a802bd77c4f0536f5a, .*\.com"
                                        className="input-dark"
                                        value={value}
                                        onBlur={formik.handleBlur}
                                        onChange={(event) => {
                                          const attributevalues =
                                            formik.values.analyzables;
                                          attributevalues[index] =
                                            event.target.value;
                                          formik.setFieldValue(
                                            "analyzables",
                                            attributevalues,
                                            true,
                                          );
                                          setInputValue(event.target.value);
                                        }}
                                        invalid={
                                          formik.touched[
                                            `analyzables-${index}`
                                          ] &&
                                          formik.errors[`analyzables-${index}`]
                                        }
                                      />
                                      <FormFeedback>
                                        {formik.errors[`analyzables-${index}`]}
                                      </FormFeedback>
                                    </Col>
                                    <Col
                                      sm={2}
                                      className="d-flex justify-content-start"
                                    >
                                      <Button
                                        color="primary"
                                        size="sm"
                                        id={`analyzables-${index}-deletebtn`}
                                        className="mx-1 rounded-1 d-flex align-items-center px-3"
                                        onClick={() =>
                                          arrayHelpers.remove(index)
                                        }
                                        disabled={
                                          formik.values.analyzables.length === 1
                                        }
                                      >
                                        <BsFillTrashFill />
                                      </Button>
                                      <Button
                                        color="primary"
                                        size="sm"
                                        id={`analyzables-${index}-addbtn`}
                                        className="mx-1 rounded-1 d-flex align-items-center px-3"
                                        onClick={() => arrayHelpers.push("")}
                                      >
                                        <BsFillPlusCircleFill />
                                      </Button>
                                    </Col>
                                  </div>
                                  <div className="row">
                                    <Col sm={3}>
                                      <small className="fst-italic">
                                        Type:
                                      </small>
                                      <small className="text-info ms-2">
                                        {inputState[value]?.type?.replace(
                                          "_",
                                          " ",
                                        )}
                                      </small>
                                    </Col>
                                    <Col
                                      sm={5}
                                      className="d-flex align-items-center "
                                    >
                                      <small className="fst-italic">
                                        Matches:
                                      </small>
                                      {inputState[value]?.type !==
                                        UserEventTypes.ANALYZABLE &&
                                      value !== "" ? (
                                        <div>
                                          <small className="text-info ms-2">
                                            {inputState[value]?.matches?.length}{" "}
                                          </small>
                                          <MdInfoOutline
                                            id="matches-infoicon"
                                            fontSize="15"
                                            className="text-info"
                                          />
                                          <UncontrolledTooltip
                                            trigger="hover"
                                            delay={{ show: 0, hide: 200 }}
                                            target="matches-infoicon"
                                            placement="right"
                                            fade={false}
                                            innerClassName="p-2 text-start text-nowrap md-fit-content"
                                          >
                                            {inputState[
                                              value
                                            ]?.matches?.toString()}
                                          </UncontrolledTooltip>
                                        </div>
                                      ) : (
                                        <small className="text-gray ms-2">
                                          supported only for wildcard
                                        </small>
                                      )}
                                    </Col>
                                  </div>
                                </div>
                              ))
                            : null}
                        </div>
                      </FormGroup>
                    )}
                  />
                </Col>
              </Row>
              <hr />
            </FormGroup>
            <FormGroup>
              <Row>
                <Col md={2} className="d-flex align-items-center">
                  <Label
                    className="me-2 mb-0 required"
                    for="userEvent__evaluation"
                  >
                    Evaluation:
                  </Label>
                </Col>
                <Col>
                  <Nav tabs className="mt-2">
                    <NavItem>
                      <NavLink
                        className={
                          advancedEvaluationTab
                            ? ""
                            : "active text-info fw-bold"
                        }
                        style={{ border: "1px solid #001d24" }}
                        onClick={() => setAdvancedEvaluationTab(false)}
                        id="userEvent__evaluation-basic"
                      >
                        Basic
                      </NavLink>
                    </NavItem>
                    <NavItem>
                      <NavLink
                        className={
                          advancedEvaluationTab
                            ? "active text-info fw-bold"
                            : ""
                        }
                        style={{ border: "1px solid #001d24" }}
                        onClick={() => setAdvancedEvaluationTab(true)}
                        id="userEvent__evaluation-advanced"
                      >
                        Advanced
                      </NavLink>
                    </NavItem>
                  </Nav>
                  <TabContent
                    activeTab={advancedEvaluationTab ? "advanced" : "basic"}
                    className="p-2 mt-2"
                  >
                    <TabPane tabId="basic">
                      <div className="my-3">
                        {evaluationOptions.map((value) => (
                          <FormGroup
                            check
                            inline
                            key={`userEvent__evaluation-basic-${value.id}`}
                          >
                            <Input
                              id={`userEvent__evaluation-basic-${value.id}`}
                              type="radio"
                              name="basic_evaluation"
                              value={value.id}
                              checked={
                                formik.values.basic_evaluation ===
                                value.id.toString()
                              }
                              onBlur={formik.handleBlur}
                              onChange={(event) => {
                                const basicEval = event.target.value;
                                formik.setFieldValue(
                                  "basic_evaluation",
                                  basicEval,
                                  false,
                                );
                                formik.setFieldValue(
                                  "evaluation",
                                  evaluationOptions[basicEval].evaluation,
                                  false,
                                );
                                formik.setFieldValue(
                                  "reliability",
                                  evaluationOptions[basicEval].reliability,
                                  // second set must trigger the validate or update evaluation with pre-populated form won't work
                                  true,
                                );
                              }}
                            />
                            <Label
                              check
                              for={`userEvent__evaluation-basic-${value.id}`}
                            >
                              <EvaluationBadge
                                id={`userEvent__evaluation-basic-${value.id}`}
                                evaluation={value.evaluation}
                                label={value.label}
                              />
                            </Label>
                          </FormGroup>
                        ))}
                      </div>
                      <div className="d-flex flex-column">
                        {((formik.values.evaluation.toString() ===
                          DataModelEvaluations.MALICIOUS &&
                          ![
                            RELIABILITY_CONFIRMED_MALICIOUS,
                            RELIABILITY_MALICIOUS,
                          ].includes(formik.values.reliability)) ||
                          (formik.values.evaluation.toString() ===
                            DataModelEvaluations.TRUSTED &&
                            ![
                              RELIABILITY_CURRENTLY_TRUSTED,
                              RELIABILITY_TRUSTED,
                            ].includes(formik.values.reliability))) && (
                          <small
                            className="d-flex align-items-center mb-0 px-2 py-1"
                            style={{
                              borderColor: "warning",
                              borderRadius: 7,
                              border: "1px solid orange",
                            }}
                          >
                            <IoMdWarning className="text-warning me-2" />
                            Advanced reliability has been set and save
                            correctly. Selecting a new basic evaluation will
                            overwrite the previous settings.
                          </small>
                        )}
                        <small>
                          {
                            evaluationOptions[formik.values.basic_evaluation]
                              ?.description
                          }
                        </small>
                      </div>
                    </TabPane>
                    <TabPane tabId="advanced">
                      <div className="d-flex row mt-3">
                        <div className="col-4">
                          {[
                            DataModelEvaluations.MALICIOUS,
                            DataModelEvaluations.TRUSTED,
                          ].map((value) => (
                            <FormGroup
                              check
                              inline
                              key={`userEvent__evaluation-advanced-${value}`}
                            >
                              <Input
                                id={`userEvent__evaluation-advanced-${value}`}
                                type="radio"
                                name="evaluation"
                                value={value}
                                checked={
                                  formik.values.evaluation?.toString() === value
                                }
                                onBlur={formik.handleBlur}
                                onChange={formik.handleChange}
                              />
                              <Label
                                check
                                for={`userEvent__evaluation-advanced-${value}`}
                              >
                                <EvaluationBadge
                                  id={`userEvent__evaluation-advanced-${value}`}
                                  evaluation={value}
                                  label={value}
                                />
                              </Label>
                            </FormGroup>
                          ))}
                        </div>
                        <FormGroup className="d-flex align-items-center col-4">
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
                  <Label
                    className="me-2 mb-0 required"
                    for="userEvent__related_threats"
                  >
                    Reason:
                  </Label>
                </Col>
                <Col md={10}>
                  <ListInput
                    id="related_threats"
                    values={formik.values.related_threats}
                    formikSetFieldValue={formik.setFieldValue}
                    formikHandlerBlur={formik.handleBlur}
                  />
                  {formik.errors["related_threats-0"] &&
                    formik.touched["related_threats-0"] && (
                      <span className="text-danger">
                        {formik.errors["related_threats-0"]}
                      </span>
                    )}
                </Col>
              </Row>
              <hr />
            </FormGroup>
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
                        label: (
                          <div
                            id={`killChainPhase__${killChainPhase}`}
                            className="d-flex justify-content-start align-items-start flex-column"
                          >
                            <div className="d-flex justify-content-start align-items-baseline flex-column">
                              <div>{killChainPhase}&nbsp;</div>
                              <div className="small text-left text-muted">
                                {DataModelKillChainPhasesDescriptions[
                                  killChainPhase.toUpperCase()
                                ] || ""}
                              </div>
                            </div>
                          </div>
                        ),
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
                disabled={!formik.isValid || formik.isSubmitting}
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

UserEventModal.propTypes = {
  analyzables: PropTypes.array,
  toggle: PropTypes.func.isRequired,
  isOpen: PropTypes.bool.isRequired,
};

UserEventModal.defaultProps = {
  analyzables: [""],
};
