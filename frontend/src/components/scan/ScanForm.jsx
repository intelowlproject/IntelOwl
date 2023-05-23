import React from "react";
import { BsFillTrashFill, BsFillPlusCircleFill } from "react-icons/bs";
import { MdEdit, MdInfoOutline } from "react-icons/md";
import {
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
  Collapse,
} from "reactstrap";
import { useNavigate } from "react-router-dom";
import { Field, Form, FieldArray, useFormik, FormikProvider } from "formik";
import useTitle from "react-use/lib/useTitle";

import {
  ContentSection,
  IconButton,
  Loader,
  MultiSelectDropdownInput,
  addToast,
} from "@certego/certego-ui";

import {
  IoIosArrowDropdownCircle,
  IoIosArrowDropupCircle,
} from "react-icons/io";
import { useQuotaBadge } from "../../hooks";
import { usePluginConfigurationStore } from "../../stores";
import { TLP_CHOICES, TLP_DESCRIPTION_MAP, scanTypes } from "../../constants";
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

const observableType2RegExMap = {
  domain: "^(?:[\\w-]{1,63}\\.)+[\\w-]{2,63}$",
  ip: "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
  url: "^.{2,20}://.+$",
  hash: "^[a-zA-Z0-9]{32,}$",
};

const sanitizeObservable = (observable) =>
  observable.replaceAll("[", "").replaceAll("]", "");

// Component
export default function ScanForm() {
  console.debug("ScanForm rendered!");

  const formik = useFormik({
    initialValues: {
      observableType: "observable",
      classification: "generic",
      observable_names: [""],
      files: [],
      analyzers: [],
      connectors: [],
      playbooks: [],
      tlp: "AMBER",
      runtime_configuration: {},
      tags: [],
      check: "check_all",
      analysisOptionValues: scanTypes.playbooks,
      hoursAgo: 24,
    },
    validate: (values) => {
      console.debug("validate - values");
      console.debug(values);

      const errors = {};

      if (analyzersError) {
        errors.analyzers = analyzersError;
      }
      if (connectorsError) {
        errors.connectors = connectorsError;
      }

      if (values.observableType === "file") {
        if (!values.files || values.files.length === 0) {
          errors.files = "required";
        }
      } else if (
        values.observable_names.filter((observable) => observable.length)
          .length === 0
      ) {
        // we cannot return a list of errors (one for each observable), or isValid doesn't work
        errors.observable_names = "observable(s) are required";
      }

      if (!TLP_CHOICES.includes(values.tlp)) {
        errors.tlp = "Invalid choice";
      }

      // check playbooks or analyzers
      if (values.playbooks.length === 0 && values.analyzers.length === 0) {
        errors.playbooks = "playbooks or analyzers required";
      }

      console.debug("formik validation errors");
      console.debug(errors);
      return errors;
    },
    onSubmit: async (values) => {
      if (values.analysisOptionValues === scanTypes.playbooks) {
        startPlaybooks(values);
        return;
      }

      const formValues = {
        ...values,
        observable_names: values.observable_names.map((observable) =>
          sanitizeObservable(observable)
        ),
        tags_labels: values.tags.map((optTag) => optTag.value.label),
        analyzers: values.analyzers.map((x) => x.value),
        connectors: values.connectors.map((x) => x.value),
      };

      if (values.analyzers.length === 0) {
        addToast("Failed!", "Please select at least one analyzer", "danger");
        return;
      }

      /* We have 2 cases:
       1) use default config -> we need the runtime_configuration field has value {}
       2) custom config -> we need to add visualizers because it's required from the backend

      Note: we don't put visualizers in the editor because it could be very verbose
      */
      if (Object.keys(formValues.runtime_configuration).length) {
        formik.values.runtime_configuration.visualizers = {};
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
  });

  /* With the setFieldValue the validation and rerender don't work properly: the last update seems to not trigger the validation
  and leaves the UI with values not valid, for this reason the scan button is disabled, but if the user set focus on the UI the last
  validation trigger and start scan is enabled. To avoid this we use this hook that force the validation when the form values change.
  
  This hook is the reason why we can disable the validation in the setFieldValue method (3rd params).
  */
  React.useEffect(() => {
    formik.validateForm();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [formik.values]);

  const [scanType, setScanType] = React.useState(
    formik.values.analysisOptionValues
  );

  const [isModalOpen, setModalOpen] = React.useState(false);
  const toggleModal = React.useCallback(
    () => setModalOpen((o) => !o),
    [setModalOpen]
  );

  const [isAdvancedSettingsOpen, toggleAdvancedSettings] =
    React.useState(false);

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
      analyzersGrouped[formik.values.classification]
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
    [analyzersGrouped, formik.values.classification]
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

  const playbookOptions = (classification) =>
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
        observable_names: values.observable_names.map((observable) =>
          sanitizeObservable(observable)
        ),
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

  console.debug(`classification: ${formik.values.classification}`);
  console.debug("formik");
  console.debug(formik);
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
          {formik.values.classification === "file" ? "Files" : "Observables"}
        </h3>
        <hr />
        <FormikProvider value={formik}>
          <Form onSubmit={formik.handleSubmit}>
            <Row>
              <div className="col-sm-3 col-form-label" />
              <FormGroup className="mb-0 d-flex col-sm-9">
                {["observable", "file"].map((ch) => (
                  <FormGroup check inline key={`observableType__${ch}`}>
                    <Col>
                      <Field
                        as={Input}
                        id={`observableType__${ch}`}
                        type="radio"
                        name="observableType"
                        value={ch}
                        onClick={(event) => {
                          formik.setFieldValue(
                            "observableType",
                            event.target.value,
                            false
                          );
                          formik.setFieldValue(
                            "classification",
                            event.target.value === "observable"
                              ? "generic"
                              : "file"
                          );
                          formik.setFieldValue("observable_names", [""], false);
                          formik.setFieldValue("files", [""], false);
                          formik.setFieldValue(
                            "analysisOptionValues",
                            scanTypes.playbooks,
                            false
                          );
                          setScanType(scanTypes.playbooks);
                          formik.setFieldValue("playbooks", [], false); // reset
                          formik.setFieldValue("analyzers", [], false); // reset
                          formik.setFieldValue("connectors", [], false); // reset
                        }}
                      />
                      <Label check>
                        {ch === "observable"
                          ? "observable (domain, IP, URL, HASH, etc...)"
                          : "file"}
                      </Label>
                    </Col>
                  </FormGroup>
                ))}
              </FormGroup>
            </Row>
            {formik.values.observableType === "observable" ? (
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
                        ? formik.values.observable_names.map((name, index) => (
                            <div
                              className="py-2 d-flex"
                              key={`observable_names.${index + 0}`}
                            >
                              <Col sm={11} className="pe-3">
                                <Field
                                  as={Input}
                                  type="text"
                                  placeholder="google.com, 8.8.8.8, https://google.com, 1d5920f4b44b27a802bd77c4f0536f5a"
                                  id={`observable_names.${index}`}
                                  name={`observable_names.${index}`}
                                  className="input-dark"
                                  invalid={
                                    Boolean(
                                      formik.errors.observable_names &&
                                        formik.errors.observable_names[index]
                                    ) &&
                                    formik.touched.observable_names &&
                                    formik.touched.observable_names[index]
                                  }
                                  onChange={(event) => {
                                    if (index === 0) {
                                      const oldClassification =
                                        formik.values.classification;
                                      let newClassification = "generic";
                                      Object.entries(
                                        observableType2RegExMap
                                      ).forEach(([typeName, typeRegEx]) => {
                                        if (
                                          new RegExp(typeRegEx).test(
                                            sanitizeObservable(
                                              event.target.value
                                            )
                                          )
                                        ) {
                                          newClassification = typeName;
                                        }
                                      });
                                      formik.setFieldValue(
                                        "classification",
                                        newClassification,
                                        false
                                      );
                                      // in case a palybook is available and i changed classification or no playbooks is selected i select a playbook
                                      if (
                                        playbookOptions(newClassification)
                                          .length > 0 &&
                                        (oldClassification !==
                                          newClassification ||
                                          formik.values.playbooks.length === 0)
                                      ) {
                                        formik.setFieldValue(
                                          "playbooks",
                                          [
                                            playbookOptions(
                                              newClassification
                                            )[0],
                                          ],
                                          false
                                        );
                                      }
                                    }
                                    const observableNames =
                                      formik.values.observable_names;
                                    observableNames[index] = event.target.value;
                                    formik.setFieldValue(
                                      "observable_names",
                                      observableNames,
                                      false
                                    );
                                  }}
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
                          ))
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
                    onChange={(event) => {
                      formik.setFieldValue(
                        "files",
                        event.currentTarget.files,
                        false
                      );
                      formik.setFieldValue("classification", "file", false);
                      if (
                        formik.values.playbooks.length === 0 &&
                        playbookOptions("file").length > 0
                      ) {
                        formik.setFieldValue(
                          "playbooks",
                          [playbookOptions("file")[0]],
                          false
                        );
                      }
                    }}
                    className="input-dark"
                    multiple
                  />
                </Col>
              </FormGroup>
            )}
            <hr />
            <Row>
              <div className="col-sm-3 col-form-label" />
              <FormGroup
                className="d-flex col-sm-9"
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
                          formik.setFieldValue("playbooks", [], false); // reset
                        }}
                      />
                      <Label check>{type_}</Label>
                    </Col>
                  </FormGroup>
                ))}
              </FormGroup>
            </Row>
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
                        <MultiSelectDropdownInput
                          options={analyzersOptions}
                          value={formik.values.analyzers}
                          onChange={(v) =>
                            formik.setFieldValue("analyzers", v, false)
                          }
                        />
                      )}
                    />
                  </Col>
                </FormGroup>
                <FormGroup row>
                  <Label sm={3} for="connectors">
                    Select Connectors
                  </Label>
                  <Col sm={9}>
                    {!(connectorsLoading || connectorsError) && (
                      <MultiSelectDropdownInput
                        options={connectorOptions}
                        value={formik.values.connectors}
                        onChange={(v) =>
                          formik.setFieldValue("connectors", v, false)
                        }
                      />
                    )}
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
                      options={playbookOptions(formik.values.classification)}
                      value={formik.values.playbooks}
                      onChange={(v) =>
                        formik.setFieldValue("playbooks", v, false)
                      }
                    />
                  </Col>
                )}
              </FormGroup>
            )}

            <hr />
            <Button
              size="sm"
              onClick={() => toggleAdvancedSettings(!isAdvancedSettingsOpen)}
              color="primary"
            >
              <span className="me-1">Advanced settings</span>
              {isAdvancedSettingsOpen ? (
                <IoIosArrowDropupCircle />
              ) : (
                <IoIosArrowDropdownCircle />
              )}
            </Button>
            <Collapse isOpen={isAdvancedSettingsOpen}>
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
                  <div>
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
                  </div>
                  <FormText>
                    {TLP_DESCRIPTION_MAP[formik.values.tlp].replace(
                      "TLP: ",
                      ""
                    )}
                  </FormText>
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
                  <FormGroup check key="checkchoice__force_new">
                    <Field
                      as={Input}
                      id="checkchoice__force_new"
                      type="radio"
                      name="check"
                      value="force_new"
                      onChange={formik.handleChange}
                    />
                    <Label check for="checkchoice__force_new">
                      Force new analysis
                    </Label>
                  </FormGroup>
                </Col>
              </FormGroup>
            </Collapse>

            <FormGroup row className="mt-2">
              <Button
                type="submit"
                /* dirty return True if values are different then default
                 we cannot run the validation on mount or we get an infinite loop.
                */
                disabled={
                  !formik.dirty || !formik.isValid || formik.isSubmitting
                }
                color="primary"
                size="lg"
                outline
                className="mx-auto rounded-0 col-sm-2 order-sm-5"
              >
                {formik.isSubmitting && <Spinner size="sm" />}Start Scan
              </Button>
            </FormGroup>
          </Form>
        </FormikProvider>
      </ContentSection>
      {/* Recent Scans */}
      <h6 className="fw-bold">Recent Scans</h6>
      <RecentScans />
    </Container>
  );
}
