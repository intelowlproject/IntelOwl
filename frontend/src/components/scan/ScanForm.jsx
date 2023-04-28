import React from "react";
import { BsFillTrashFill, BsFillPlusCircleFill } from "react-icons/bs";
import { MdEdit, MdInfoOutline } from "react-icons/md";
import {
  FormFeedback,
  FormGroup,
  Label,
  Container,
  Col,
  Row,
  FormText,
  Input,
  Spinner,
  Button,
  UncontrolledTooltip,
} from "reactstrap";
import { useNavigate } from "react-router-dom";
import { ErrorMessage, Field, Form, Formik, FieldArray } from "formik";
import useTitle from "react-use/lib/useTitle";

import {
  ContentSection,
  IconButton,
  Loader,
  MultiSelectDropdownInput,
  addToast,
} from "@certego/certego-ui";

import { useQuotaBadge } from "../../hooks";
import { usePluginConfigurationStore } from "../../stores";
import {
  TLP_CHOICES,
  TLP_DESCRIPTION_MAP,
  OBSERVABLE_TYPES,
  ALL_CLASSIFICATIONS,
  scanTypes,
} from "../../constants";
import { TLPTag, markdownToHtml } from "../common";
import {
  RuntimeConfigurationModal,
  RecentScans,
  TagSelectInput,
} from "./utils";
import { createJob, createPlaybookJob } from "./api";

// constants
const groupAnalyzers = (analyzersList) => {
  const grouped = {
    ip: [],
    hash: [],
    domain: [],
    url: [],
    generic: [],
    file: [],
  };
  analyzersList.forEach((obj) => {
    // filter on basis of type
    if (obj.type === "file") {
      grouped.file.push(obj);
    } else {
      obj.observable_supported.forEach((clsfn) => grouped[clsfn].push(obj));
    }
  });
  return grouped;
};

const groupPlaybooks = (playbooksList) => {
  const grouped = {
    ip: [],
    hash: [],
    domain: [],
    url: [],
    generic: [],
    file: [],
  };

  playbooksList.forEach((obj) => {
    // filter on basis of type
    if (obj.type.includes("file")) {
      grouped.file.push(obj);
    }

    obj.type.forEach((clsfn) => {
      if (clsfn !== "file") {
        grouped[clsfn].push(obj);
      }
    });
  });
  return grouped;
};

const stateSelector = (state) => [
  state.analyzersLoading,
  state.connectorsLoading,
  state.playbooksLoading,
  state.analyzersError,
  state.connectorsError,
  state.playbooksError,
  groupAnalyzers(state.analyzers),
  state.connectors,
  groupPlaybooks(state.playbooks),
];

const checkChoices = [
  {
    value: "running_only",
    label: "Do not execute if a similar analysis is currently running",
  },
  {
    value: "force_new",
    label: "Force new analysis",
  },
];
const observableType2PropsMap = {
  ip: {
    placeholder: "8.8.8.8",
    title: "invalid IP address",
    pattern:
      "((^s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]).){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))s*$)|(^s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))(%.+)?s*$))",
  },
  url: {
    placeholder: "http://example.com/",
    title: "invalid URL",
    pattern: "^.{2,20}://.+$",
  },
  domain: {
    placeholder: "scanme.org",
    title: "invalid Domain",
    pattern: "^(.?.?.?[-_a-zA-Z0-9]+)+$", //eslint-disable-line
  },
  hash: {
    placeholder: "446c5fbb11b9ce058450555c1c27153c",
    title: "invalid Hash",
    pattern: "^[a-zA-Z0-9]{4,}$",
  },
  generic: {
    placeholder: "email, phone no., city, country, registry etc.",
    title: "invalid Generic Observable",
    pattern: ".+",
  },
};

const initialValues = {
  classification: "ip",
  observable_names: [""],
  files: [],
  analyzers: [],
  connectors: [],
  playbooks: [],
  tlp: "CLEAR",
  runtime_configuration: {},
  tags: [],
  check: "check_all",
  analysisOptionValues: "Analyzers/Connectors",
  hoursAgo: 24,
};

// Component
export default function ScanForm() {
  console.debug("ScanForm rendered!");

  // local state
  const [classification, setClassification] = React.useState(
    initialValues.classification
  );

  const [scanType, setScanType] = React.useState(
    initialValues.analysisOptionValues
  );

  const [isModalOpen, setModalOpen] = React.useState(false);
  const toggleModal = React.useCallback(
    () => setModalOpen((o) => !o),
    [setModalOpen]
  );

  // page title
  useTitle("IntelOwl | Scan", { restoreOnUnmount: true });

  // router navigation
  const navigate = useNavigate();

  // use custom hooks
  const [{ MonthBadge, TotalBadge, QuotaInfoIcon }, refetchQuota, _quota] =
    useQuotaBadge();

  // API/ store
  const [
    analyzersLoading,
    connectorsLoading,
    playbooksLoading,
    analyzersError,
    connectorsError,
    playbooksError,
    analyzersGrouped,
    connectors,
    playbooksGrouped,
  ] = usePluginConfigurationStore(stateSelector);

  const analyzersOptions = React.useMemo(
    () =>
      analyzersGrouped[classification]
        .map((v) => ({
          isDisabled: !v.verification.configured || v.disabled,
          value: v.name,
          label: (
            <div className="d-flex justify-content-start align-items-start flex-column">
              <div className="d-flex justify-content-start align-items-baseline flex-column">
                <div>{v.name}&nbsp;</div>
                <div className="small text-start text-muted">
                  {markdownToHtml(v.description)}
                </div>
              </div>
              {!v.verification.configured && (
                <div className="small text-danger">
                  ⚠ {v.verification.details}
                </div>
              )}
            </div>
          ),
          labelDisplay: v.name,
        }))
        .sort((a, b) =>
          // eslint-disable-next-line no-nested-ternary
          a.isDisabled === b.isDisabled ? 0 : a.isDisabled ? 1 : -1
        ),
    [analyzersGrouped, classification]
  );
  const connectorOptions = React.useMemo(
    () =>
      connectors
        .map((v) => ({
          isDisabled: !v.verification.configured || v.disabled,
          value: v.name,
          label: (
            <div className="d-flex justify-content-start align-items-start flex-column">
              <div className="d-flex justify-content-start align-items-baseline flex-column">
                <div>{v.name}&nbsp;</div>
                <div className="small text-start text-muted">
                  {markdownToHtml(v.description)}
                </div>
              </div>
              {!v.verification.configured && (
                <div className="small text-danger">
                  ⚠ {v.verification.details}
                </div>
              )}
            </div>
          ),
          labelDisplay: v.name,
        }))
        .sort((a, b) =>
          // eslint-disable-next-line no-nested-ternary
          a.isDisabled === b.isDisabled ? 0 : a.isDisabled ? 1 : -1
        ),
    [connectors]
  );

  const playbookOptions = React.useMemo(
    () =>
      playbooksGrouped[classification]
        .map((v) => ({
          isDisabled: v.disabled,
          value: v.name,
          label: (
            <div className="d-flex justify-content-start align-items-start flex-column">
              <div className="d-flex justify-content-start align-items-baseline flex-column">
                <div>{v.name}&nbsp;</div>
                <div className="small text-left text-muted">
                  {markdownToHtml(v.description)}
                </div>
              </div>
            </div>
          ),
          labelDisplay: v.name,
        }))
        .sort((a, b) =>
          // eslint-disable-next-line no-nested-ternary
          a.isDisabled === b.isDisabled ? 0 : a.isDisabled ? 1 : -1
        ),
    [playbooksGrouped, classification]
  );

  // callbacks
  const onValidate = React.useCallback(
    (values) => {
      const errors = {};

      if (analyzersError) {
        errors.analyzers = analyzersError;
      }
      if (connectorsError) {
        errors.connectors = connectorsError;
      }

      if (values.classification === "file") {
        if (!values.files || values.files.length === 0) {
          errors.files = "required";
        }
      } else if (values.observable_names && values.observable_names.length) {
        if (!TLP_CHOICES.includes(values.tlp)) {
          errors.tlp = "Invalid choice";
        }
      }
      return errors;
    },
    [analyzersError, connectorsError]
  );

  const ValidatePlaybooks = React.useCallback(
    (values) => {
      const errors = {};
      if (playbooksError) {
        errors.playbooks = playbooksError;
      }
      if (values.playbooks.length === 0) {
        return `Please select a playbook!`;
      }
      if (values.classification === "file") {
        if (!values.files || values.files.length === 0) {
          errors.files = "required";
        }
      } else if (values.observable_names && values.observable_names.length) {
        if (!TLP_CHOICES.includes(values.tlp)) {
          errors.tlp = "Invalid choice";
        }
      }
      return errors;
    },
    [playbooksError]
  );

  const startPlaybooks = React.useCallback(
    async (values) => {
      const formValues = {
        ...values,
        tlp: values.tlp,
        tags_labels: values.tags.map((optTag) => optTag.value.label),
        playbooks: values.playbooks.map((x) => x.value),
      };

      const errors = ValidatePlaybooks(values);

      if (Object.keys(errors).length !== 0) {
        addToast("Failed!", JSON.stringify(errors), "danger");
        return;
      }

      try {
        const jobIds = await createPlaybookJob(formValues);

        if (jobIds.length > 1) {
          setTimeout(() => navigate(`/jobs/`), 1000);
        } else {
          setTimeout(() => navigate(`/jobs/${jobIds[0]}`), 1000);
        }
      } catch (e) {
        // handled inside createPlaybookJob
      } finally {
        refetchQuota();
      }
    },
    [navigate, refetchQuota, ValidatePlaybooks]
  );

  const onSubmit = React.useCallback(
    async (values, formik) => {
      if (values.analysisOptionValues === scanTypes.playbooks) {
        startPlaybooks(values);
        return;
      }

      const formValues = {
        ...values,
        tags_labels: values.tags.map((optTag) => optTag.value.label),
        analyzers: values.analyzers.map((x) => x.value),
        connectors: values.connectors.map((x) => x.value),
      };
      /* We have 2 cases:
       1) use default config -> we need the runtime_configuration field has value {}
       2) custom config -> we need to add visualizers because it's required from the backend

      Note: we don't put visualizers in the editor because it could be very verbose
      */
      if (Object.keys(formValues.runtime_configuration).length) {
        formValues.runtime_configuration.visualizers = {};
      }

      console.debug("ScanFrom - onSubmit - formValues");
      console.debug(formValues);

      try {
        const jobIds = await createJob(formValues);
        if (jobIds.length > 1) {
          setTimeout(() => navigate(`/jobs/`), 1000);
        } else {
          setTimeout(() => navigate(`/jobs/${jobIds[0]}`), 1000);
        }
      } catch (e) {
        // handled inside createJob
      } finally {
        refetchQuota();
        formik.setSubmitting(false);
      }
    },
    [navigate, refetchQuota, startPlaybooks]
  );

  return (
    <Container className="col-lg-12 col-xl-7">
      {/* Quota badges */}
      <ContentSection className="bg-body mb-2 d-flex-center">
        <MonthBadge className="me-2 text-larger" />
        <TotalBadge className="ms-2 me-3 text-larger" />
        <QuotaInfoIcon />
      </ContentSection>
      {/* Form */}
      <ContentSection id="ScanForm" className="mt-3 bg-body shadow">
        <h3 className="fw-bold">
          Scan&nbsp;
          {classification === "file" ? "Files" : "Observables"}
        </h3>
        <hr />
        <Formik
          initialValues={initialValues}
          validate={onValidate}
          onSubmit={onSubmit}
          validateOnMount
        >
          {(formik) => (
            <Form>
              <FormGroup className="d-flex justify-content-center">
                {ALL_CLASSIFICATIONS.map((ch) => (
                  <FormGroup check inline key={`classification__${ch}`}>
                    <Col>
                      <Field
                        as={Input}
                        id={`classification__${ch}`}
                        type="radio"
                        name="classification"
                        value={ch}
                        onClick={() => {
                          setClassification(ch);
                          formik.setFieldValue("analyzers", []); // reset
                        }}
                      />
                      <Label check>{ch}</Label>
                    </Col>
                  </FormGroup>
                ))}
              </FormGroup>
              {OBSERVABLE_TYPES.includes(formik.values.classification) ? (
                <FieldArray
                  name="observable_names"
                  render={(arrayHelpers) => (
                    <FormGroup row>
                      <Label className="required" sm={3} for="observable_name">
                        Observable Value(s)
                      </Label>
                      <Col sm={9}>
                        <div className="invalid-feedback d-block">
                          {formik.errors.no_observables}
                        </div>
                        {formik.values.observable_names &&
                        formik.values.observable_names.length > 0
                          ? formik.values.observable_names.map(
                              (name, index) => (
                                <div
                                  className="py-2 d-flex"
                                  key={`observable_names.${index + 0}`}
                                >
                                  <Col sm={11} className="pe-3">
                                    <Field
                                      as={Input}
                                      type="text"
                                      id={`observable_names.${index}`}
                                      name={`observable_names.${index}`}
                                      className="input-dark"
                                      invalid={
                                        Boolean(
                                          formik.errors.observable_names &&
                                            formik.errors.observable_names[
                                              index
                                            ]
                                        ) &&
                                        formik.touched.observable_names &&
                                        formik.touched.observable_names[index]
                                      }
                                      {...observableType2PropsMap[
                                        formik.values.classification
                                      ]}
                                    />
                                    <ErrorMessage
                                      component={FormFeedback}
                                      name={`observable_names.${index}`}
                                    />
                                  </Col>
                                  <Button
                                    color="primary"
                                    className="mx-auto rounded-1 text-larger col-sm-1"
                                    onClick={() => arrayHelpers.remove(index)}
                                  >
                                    <BsFillTrashFill />
                                  </Button>
                                </div>
                              )
                            )
                          : null}
                        <Row className="mb-2 mt-0 pt-0">
                          <Button
                            color="primary"
                            size="sm"
                            className="mx-auto rounded-1 mx-auto col-sm-auto"
                            onClick={() => arrayHelpers.push("")}
                          >
                            <BsFillPlusCircleFill /> Add new value
                          </Button>
                        </Row>
                      </Col>
                    </FormGroup>
                  )}
                />
              ) : (
                <FormGroup row>
                  <Label className="required" sm={3} for="files">
                    File(s)
                  </Label>
                  <Col sm={9}>
                    <Input
                      type="file"
                      id="file"
                      name="files"
                      onChange={(event) =>
                        formik.setFieldValue("files", event.currentTarget.files)
                      }
                      className="input-dark"
                      multiple
                    />
                  </Col>
                </FormGroup>
              )}
              <hr />
              <FormGroup
                className="d-flex justify-content-center"
                style={{ marginTop: "10px" }}
              >
                {Object.values(scanTypes).map((type_) => (
                  <FormGroup check inline key={`analysistype__${type_}`}>
                    <Col>
                      <Field
                        as={Input}
                        id={`analysistype__${type_}`}
                        type="radio"
                        name="analysisOptionValues"
                        value={type_}
                        onClick={() => {
                          setScanType(type_);
                          formik.setFieldValue("playbooks", []); // reset
                        }}
                      />
                      <Label check>{type_}</Label>
                    </Col>
                  </FormGroup>
                ))}
              </FormGroup>
              {scanType === scanTypes.analyzers_and_connectors && (
                <>
                  <FormGroup row>
                    <Label sm={3} for="analyzers">
                      Select Analyzers
                    </Label>
                    <Col sm={9}>
                      <Loader
                        loading={analyzersLoading}
                        error={analyzersError}
                        render={() => (
                          <>
                            <MultiSelectDropdownInput
                              options={analyzersOptions}
                              value={formik.values.analyzers}
                              onChange={(v) =>
                                formik.setFieldValue("analyzers", v)
                              }
                            />
                            <FormText>
                              Default: all configured analyzers are triggered.
                            </FormText>
                          </>
                        )}
                      />
                      <ErrorMessage component={FormFeedback} name="analyzers" />
                    </Col>
                  </FormGroup>
                  <FormGroup row>
                    <Label sm={3} for="connectors">
                      Select Connectors
                    </Label>
                    <Col sm={9}>
                      {!(connectorsLoading || connectorsError) && (
                        <>
                          <MultiSelectDropdownInput
                            options={connectorOptions}
                            value={formik.values.connectors}
                            onChange={(v) =>
                              formik.setFieldValue("connectors", v)
                            }
                          />
                          <FormText>
                            Default: all configured connectors are triggered.
                          </FormText>
                        </>
                      )}
                      <ErrorMessage
                        component={FormFeedback}
                        name="connectors"
                      />
                    </Col>
                  </FormGroup>
                  <FormGroup row>
                    <Label sm={3} for="scanform-runtimeconf-editbtn">
                      Runtime Configuration
                    </Label>
                    <Col sm={9}>
                      <IconButton
                        id="scanform-runtimeconf-editbtn"
                        Icon={MdEdit}
                        title="Edit runtime configuration"
                        titlePlacement="top"
                        size="sm"
                        color="tertiary"
                        disabled={
                          !(
                            formik.values.analyzers.length > 0 ||
                            formik.values.connectors.length > 0
                          )
                        }
                        onClick={toggleModal}
                      />
                      {isModalOpen && (
                        <RuntimeConfigurationModal
                          isOpen={isModalOpen}
                          toggle={toggleModal}
                          formik={formik}
                        />
                      )}
                    </Col>
                  </FormGroup>
                </>
              )}
              {scanType === scanTypes.playbooks && (
                <FormGroup row>
                  <Label sm={3} htmlFor="playbooks">
                    Select Playbooks
                  </Label>
                  {!(playbooksLoading || playbooksError) && (
                    <Col sm={9}>
                      <MultiSelectDropdownInput
                        options={playbookOptions}
                        value={formik.values.playbooks}
                        onChange={(v) => formik.setFieldValue("playbooks", v)}
                      />
                    </Col>
                  )}
                </FormGroup>
              )}

              <hr />
              <FormGroup row>
                <Label sm={3} id="scanform-tagselectinput">
                  Tags
                </Label>
                <Col sm={9}>
                  <TagSelectInput
                    id="scanform-tagselectinput"
                    selectedTags={formik.values.tags}
                    setSelectedTags={(v) =>
                      formik.setFieldValue("tags", v, false)
                    }
                  />
                </Col>
              </FormGroup>
              <FormGroup row>
                <Label sm={3}>TLP</Label>
                <Col sm={9}>
                  {TLP_CHOICES.map((ch) => (
                    <FormGroup inline check key={`tlpchoice__${ch}`}>
                      <Label check for={`tlpchoice__${ch}`}>
                        <TLPTag value={ch} />
                      </Label>
                      <Field
                        as={Input}
                        id={`tlpchoice__${ch}`}
                        type="radio"
                        name="tlp"
                        value={ch}
                        invalid={formik.errors.tlp && formik.touched.tlp}
                        onChange={formik.handleChange}
                      />
                    </FormGroup>
                  ))}
                  <FormText>
                    {TLP_DESCRIPTION_MAP[formik.values.tlp].replace(
                      "TLP: ",
                      ""
                    )}
                  </FormText>
                  <ErrorMessage component={FormFeedback} name="tlp" />
                </Col>
              </FormGroup>

              <FormGroup row className="mt-2">
                <Label sm={3}>Scan configuration</Label>
                <Col sm={9}>
                  <FormGroup check key="checkchoice__check_all">
                    <Field
                      as={Input}
                      id="checkchoice__check_all"
                      type="radio"
                      name="check"
                      value="check_all"
                      onChange={formik.handleChange}
                    />
                    <div className="d-flex align-items-center">
                      <Label
                        check
                        for="checkchoice__check_all"
                        className="col-8"
                      >
                        Do not execute if a similar analysis is currently
                        running or reported without fails
                      </Label>
                      <div className="col-4 d-flex align-items-center">
                        H:
                        <div className="col-4 mx-1">
                          <Field
                            as={Input}
                            id="checkchoice__check_all__minutes_ago"
                            type="number"
                            name="hoursAgo"
                            onChange={formik.handleChange}
                          />
                        </div>
                        <div className="col-2">
                          <MdInfoOutline id="minutes-ago-info-icon" />
                          <UncontrolledTooltip
                            target="minutes-ago-info-icon"
                            placement="right"
                            fade={false}
                            innerClassName="p-2 border border-info text-start text-nowrap md-fit-content"
                          >
                            <span>
                              Max age (in hours) for the similar analysis.
                              <br />
                              The default value is 24 hours (1 day).
                              <br />
                              Empty value takes all the previous analysis.
                            </span>
                          </UncontrolledTooltip>
                        </div>
                      </div>
                    </div>
                  </FormGroup>
                  {checkChoices.map((ch) => (
                    <FormGroup check key={`checkchoice__${ch.value}`}>
                      <Field
                        as={Input}
                        id={`checkchoice__${ch.value}`}
                        type="radio"
                        name="check"
                        value={ch.value}
                        onChange={formik.handleChange}
                      />
                      <Label check for={`checkchoice__${ch.value}`}>
                        {ch.label}
                      </Label>
                    </FormGroup>
                  ))}
                </Col>
              </FormGroup>

              <FormGroup row className="mt-2">
                <Button
                  type="submit"
                  disabled={!(formik.isValid || formik.isSubmitting)}
                  color="primary"
                  size="lg"
                  outline
                  className="mx-auto rounded-0 col-sm-2 order-sm-5"
                >
                  {formik.isSubmitting && <Spinner size="sm" />}Start Scan
                </Button>
              </FormGroup>
            </Form>
          )}
        </Formik>
      </ContentSection>
      {/* Recent Scans */}
      <h6 className="fw-bold">Recent Scans</h6>
      <RecentScans />
    </Container>
  );
}
