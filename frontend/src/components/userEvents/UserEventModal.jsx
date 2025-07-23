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
} from "reactstrap";
import PropTypes from "prop-types";
import { useFormik, FormikProvider, FieldArray } from "formik";
import axios from "axios";
import { BsFillTrashFill, BsFillPlusCircleFill } from "react-icons/bs";
import { MdInfoOutline } from "react-icons/md";

import {
  ArrowToggleIcon,
  addToast,
  useDebounceInput,
} from "@certego/certego-ui";

import {
  USER_EVENT_ANALYZABLE,
  USER_EVENT_IP_WILDCARD,
  USER_EVENT_DOMAIN_WILDCARD,
} from "../../constants/apiURLs";

import {
  Evaluations,
  DataModelKillChainPhases,
} from "../../constants/dataModelConst";
import { ListInput } from "../common/form/ListInput";
import { TagSelectInput } from "../common/form/TagSelectInput";
import {
  DecayProgressionTypes,
  DecayProgressionDescription,
  UserEventTypes,
} from "../../constants/userEventsConst";
import { useAuthStore } from "../../stores/useAuthStore";
import {
  IP_REGEX,
  DOMAIN_REGEX,
  URL_REGEX,
  HASH_REGEX,
} from "../../constants/regexConst";

export function UserEventModal({ analyzables, toggle, isOpen }) {
  console.debug("UserEventModal rendered!");

  const [user] = useAuthStore((state) => [state.user]);
  const [isOpenAdvancedFields, setIsOpenAdvancedFields] = React.useState(false);

  const [inputValue, setInputValue] = React.useState("");
  const [wildcard, setWildcard] = React.useState("");
  const [inputTypes, setInputTypes] = React.useState({});

  const formik = useFormik({
    initialValues: {
      // base data model fields
      analyzables: analyzables.map((analyzable) => analyzable?.name || ""),
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
      if (
        values.related_threats.length === 1 &&
        values.related_threats[0] === ""
      ) {
        errors.related_threats = "A comment is required";
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
      const editedFields = {};
      Object.entries(formik.values).forEach(([key, value]) => {
        if (
          JSON.stringify(value) !== JSON.stringify(formik.initialValues[key]) &&
          key !== "analyzables"
        ) {
          editedFields[key] = value;
        }
      });

      const apiCalls = [];

      formik.values.analyzables.forEach((analyzable) => {
        const evaluation = {
          decay_progression: formik.values.decay_progression,
          decay_timedelta_days: formik.values.decay_timedelta_days,
          data_model_content: {
            ...editedFields,
            reliability: formik.values.reliability,
          },
        };

        if (inputTypes[analyzable].type === UserEventTypes.IP_WILDCARD) {
          evaluation.network = analyzable;
          axios
            .get(
              `${USER_EVENT_IP_WILDCARD}?username=${user.username}&network=${analyzable}`,
            )
            .then((resp) => {
              if (resp.data.count === 0) {
                // create a new evaluation
                apiCalls.push(
                  axios.post(`${USER_EVENT_IP_WILDCARD}`, evaluation),
                );
              } else {
                // edit an existing evaluation
                apiCalls.push(
                  axios.patch(
                    `${USER_EVENT_IP_WILDCARD}/${resp.data.results[0].id}`,
                    evaluation,
                  ),
                );
              }
            });
        } else if (
          inputTypes[analyzable].type === UserEventTypes.DOMAIN_WILDCARD
        ) {
          evaluation.query = analyzable;
          axios
            .get(
              `${USER_EVENT_DOMAIN_WILDCARD}?username=${user.username}&query=${analyzable}`,
            )
            .then((resp) => {
              if (resp.data.count === 0) {
                // create a new evaluation
                apiCalls.push(
                  axios.post(`${USER_EVENT_DOMAIN_WILDCARD}`, evaluation),
                );
              } else {
                // edit an existing evaluation
                apiCalls.push(
                  axios.patch(
                    `${USER_EVENT_DOMAIN_WILDCARD}/${resp.data.results[0].id}`,
                    evaluation,
                  ),
                );
              }
            });
        } else {
          evaluation.analyzable = { name: analyzable };
          axios
            .get(
              `${USER_EVENT_ANALYZABLE}?username=${user.username}&analyzable_name=${analyzable}`,
            )
            .then((resp) => {
              if (resp.data.count === 0) {
                // create a new evaluation
                apiCalls.push(
                  axios.post(`${USER_EVENT_ANALYZABLE}`, evaluation),
                );
              } else {
                // edit an existing evaluation
                apiCalls.push(
                  axios.patch(
                    `${USER_EVENT_ANALYZABLE}/${resp.data.results[0].id}`,
                    evaluation,
                  ),
                );
              }
            });
        }
      });

      const failed = [];
      const response = await Promise.allSettled(apiCalls);
      response.forEach((promise, index) => {
        if (promise.status === "rejected")
          failed.push(formik.values.analyzables[index]);
      });
      if (failed.length === 0) {
        addToast("Evaluation added successfully", null, "success");
        formik.setSubmitting(false);
        formik.resetForm();
        toggle(false);
      } else {
        addToast(
          `Failed to add evaluation for: ${failed.toString()}`,
          null,
          "danger",
        );
        formik.setFieldValue("analyzables", failed, false);
      }
      return null;
    },
  });

  React.useEffect(() => {
    const obj = {};
    formik.initialValues.analyzables.forEach((analyzable) => {
      if (analyzable !== "") {
        obj[analyzable] = { type: UserEventTypes.ANALYZABLE };
      }
    });
    setInputTypes({ ...inputTypes, ...obj });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [formik.initialValues.analyzables]);

  useDebounceInput(inputValue, 1000, setWildcard);

  // ip/domain wildcard matches
  React.useEffect(() => {
    if (wildcard !== "") {
      // check ip wildcard
      if (
        IP_REGEX.test(wildcard.split(/[/]/)[0]) &&
        wildcard.split(/[/]/).length === 2
      ) {
        axios
          .put(`${USER_EVENT_IP_WILDCARD}/validate`, { network: wildcard })
          .then((response) => {
            setInputTypes({
              ...inputTypes,
              [wildcard]: {
                type: UserEventTypes.IP_WILDCARD,
                matchesNumber: response.data.length,
                matches: response.data,
              },
            });
          })
          .catch((error) => console.debug(error));
      } else if (
        !DOMAIN_REGEX.test(wildcard) &&
        !IP_REGEX.test(wildcard) &&
        !URL_REGEX.test(wildcard) &&
        !HASH_REGEX.test(wildcard)
      ) {
        // check domain wildcard
        axios
          .put(`${USER_EVENT_DOMAIN_WILDCARD}/validate`, { query: wildcard })
          .then((response) => {
            setInputTypes({
              ...inputTypes,
              [wildcard]: {
                type: UserEventTypes.DOMAIN_WILDCARD,
                matchesNumber: response.data.length,
                matches: response.data,
              },
            });
          })
          .catch((error) => console.debug(error));
      } else {
        setInputTypes({
          ...inputTypes,
          [wildcard]: { type: UserEventTypes.ANALYZABLE },
        });
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [wildcard]);

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
      toggle={() => toggle(false)}
    >
      <ModalHeader className="mx-2" toggle={() => toggle(false)}>
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
                                      />
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
                                        {inputTypes[value]?.type?.replace(
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
                                      {inputTypes[value]?.type !==
                                        UserEventTypes.ANALYZABLE &&
                                      value !== "" ? (
                                        <div>
                                          <small className="text-info ms-2">
                                            {inputTypes[value]?.matchesNumber}{" "}
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
                                            {inputTypes[
                                              value
                                            ]?.matches.toString()}
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
                <Col md={8} className="d-flex align-items-center">
                  <Input
                    id="userEvent__evaluation"
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
                          key={`userEvent__evaluation-select-option-${value}`}
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
                    for="userEvent__related_threats"
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
                <Col md={8} className="d-flex align-items-center">
                  <Input
                    id="userEvent__kill_chain_phase"
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
                          key={`userEvent__kill_chain_phase-select-option-${value}`}
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
              <Label sm={2} for="userEvent__tags">
                Tags:
              </Label>
              <Col sm={8}>
                <TagSelectInput
                  id="userEvent-tagselectinput"
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
                      <Label className="me-2 mb-0" for="userEvent__reliability">
                        Reliability:
                      </Label>
                    </Col>
                    <Col md={8} className="d-flex-column align-items-center">
                      <Input
                        id="userEvent__reliability"
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

UserEventModal.propTypes = {
  analyzables: PropTypes.arrayOf(Object),
  toggle: PropTypes.func.isRequired,
  isOpen: PropTypes.bool.isRequired,
};

UserEventModal.defaultProps = {
  analyzables: [""],
};
