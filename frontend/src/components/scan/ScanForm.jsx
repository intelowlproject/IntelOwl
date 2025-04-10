import React, { useEffect } from "react";
import { BsFillTrashFill, BsFillPlusCircleFill } from "react-icons/bs";
import { MdEdit } from "react-icons/md";
import { RiFileAddLine } from "react-icons/ri";
import {
  FormGroup,
  Label,
  Container,
  Col,
  Row,
  Input,
  Spinner,
  Button,
  Collapse,
} from "reactstrap";
import { useNavigate, useSearchParams } from "react-router-dom";
import {
  Field,
  Form,
  FieldArray,
  useFormik,
  FormikProvider,
  ErrorMessage,
} from "formik";
import useTitle from "react-use/lib/useTitle";

import {
  ContentSection,
  IconButton,
  useDebounceInput,
} from "@certego/certego-ui";

import {
  IoIosArrowDropdownCircle,
  IoIosArrowDropupCircle,
} from "react-icons/io";
import { useQuotaBadge } from "../../hooks";
import { usePluginConfigurationStore } from "../../stores/usePluginConfigurationStore";
import { useOrganizationStore } from "../../stores/useOrganizationStore";
import {
  TLPs,
  TlpChoices,
  ScanTypes,
  ScanModesNumeric,
} from "../../constants/advancedSettingsConst";
import { JobResultSections } from "../../constants/miscConst";
import { RuntimeConfigurationModal } from "./utils/RuntimeConfigurationModal";
import { MultipleObservablesModal } from "./utils/MultipleObservablesModal";
import RecentScans from "./utils/RecentScans";
import { TagSelectInput } from "../common/form/TagSelectInput";
import { createJob } from "./scanApi";
import { useGuideContext } from "../../contexts/GuideContext";
import { parseScanCheckTime } from "../../utils/time";
import { JobTypes, ObservableClassifications } from "../../constants/jobConst";
import {
  sanitizeObservable,
  getObservableClassification,
} from "../../utils/observables";
import { SpinnerIcon } from "../common/icon/actionIcons";
import {
  AnalyzersMultiSelectDropdownInput,
  ConnectorsMultiSelectDropdownInput,
  playbookOptions,
  PlaybookMultiSelectDropdownInput,
} from "../common/form/pluginsMultiSelectDropdownInput";
import {
  TLPSelectInputLabel,
  TLPSelectInput,
} from "../common/form/TLPSelectInput";
import { ScanConfigSelectInput } from "../common/form/ScanConfigSelectInput";

function DangerErrorMessage(fieldName) {
  return (
    <ErrorMessage
      name={fieldName}
      render={(msg) => <span className="text-danger">{msg}</span>}
    />
  );
}

// Component
export default function ScanForm() {
  const [searchParams, _] = useSearchParams();
  const observableParam = searchParams.get(JobTypes.OBSERVABLE);
  const isSampleParam = searchParams.get("isSample") === "true";
  const investigationIdParam = searchParams.get("investigation") || null;
  const parentIdParam = searchParams.get("parent");
  const { guideState, setGuideState } = useGuideContext();

  const { pluginsState: organizationPluginsState } = useOrganizationStore(
    React.useCallback(
      (state) => ({
        pluginsState: state.pluginsState,
      }),
      [],
    ),
  );

  /* Recent Scans states - inputValue is used to save the user typing (this state changes for each character that is typed), 
  recentScansInput is used for rendering RecentScans component only once per second
  */
  const [inputValue, setInputValue] = React.useState("");
  const [recentScansInput, setRecentScansInput] = React.useState("");

  React.useEffect(() => {
    if (guideState.tourActive) {
      setTimeout(() => {
        setGuideState({ run: true, stepIndex: 3 });
      }, 100);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  console.debug(
    `ScanForm rendered! Observable in GET param: ${observableParam}`,
  );

  const formik = useFormik({
    initialValues: {
      observableType: JobTypes.OBSERVABLE,
      classification: ObservableClassifications.GENERIC,
      observable_names: [""],
      files: [],
      analyzers: [],
      connectors: [],
      // playbook is an object, but if we use {} as default the UI component to select playbooks doesn's show the placeholder
      playbook: "",
      tlp: TLPs.AMBER,
      runtime_configuration: {},
      tags: [],
      scan_mode: ScanModesNumeric.CHECK_PREVIOUS_ANALYSIS,
      analysisOptionValues: ScanTypes.playbooks,
      scan_check_time: 24,
    },
    validate: (values) => {
      console.debug("validate - values");
      console.debug(values);

      const errors = {};

      // error in plugins download
      if (analyzersError) {
        errors.analyzers = analyzersError;
      }
      if (connectorsError) {
        errors.connectors = connectorsError;
      }
      if (playbooksError) {
        errors.playbook = playbooksError;
      }

      if (values.observableType === JobTypes.FILE) {
        // this is an edge case
        if (
          !values.files ||
          values.files.length === 0 ||
          (values.files.length === 1 && values.files[0] === "")
        ) {
          errors.files = "required";
        }
      } else if (
        values.observable_names.filter((observable) => observable.length)
          .length === 0
      ) {
        // we cannot return a list of errors (one for each observable), or isValid doesn't work
        errors.observable_names = "observable(s) are required";
      }

      // check playbook or analyzer selections based on the user selection
      if (
        values.analysisOptionValues === ScanTypes.playbooks &&
        Object.keys(values.playbook).length === 0
      ) {
        errors.playbook = "playbook required";
      }
      if (
        values.analysisOptionValues === ScanTypes.analyzers_and_connectors &&
        values.analyzers.length === 0 &&
        values.connectors.length === 0
      ) {
        errors.analyzers = "analyzers or connectors required";
        errors.connectors = "analyzers or connectors required";
      }

      if (!TlpChoices.includes(values.tlp)) {
        errors.tlp = "Invalid choice";
      }

      console.debug("formik validation errors");
      console.debug(errors);
      return errors;
    },
    onSubmit: async (values) => {
      const response = await createJob(
        values.observableType === JobTypes.OBSERVABLE
          ? values.observable_names
          : values.files,
        values.classification,
        values.playbook.value,
        values.analyzers.map((analyzer) => analyzer.value),
        values.connectors.map((connector) => connector.value),
        values.runtime_configuration,
        values.tags.map((optTag) => optTag.value.label),
        values.tlp,
        values.scan_mode,
        values.scan_check_time,
        investigationIdParam,
        parentIdParam,
      );

      // multiple job or investigation id in GET param
      if (response.investigationId) {
        setTimeout(
          () => navigate(`/investigation/${response.investigationId}`),
          1000,
        );
      } else {
        // single job or pivot
        setTimeout(
          () =>
            navigate(
              `/jobs/${response.jobIds[0]}/${JobResultSections.VISUALIZER}/`,
            ),
          1000,
        );
      }

      refetchQuota();
      formik.setSubmitting(false);
    },
  });

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
    visualizersLoading,
    pivotsLoading,
    playbooksLoading,
    analyzersError,
    connectorsError,
    playbooksError,
    playbooks,
  ] = usePluginConfigurationStore((state) => [
    state.analyzersLoading,
    state.connectorsLoading,
    state.visualizersLoading,
    state.pivotsLoading,
    state.playbooksLoading,
    state.analyzersError,
    state.connectorsError,
    state.playbooksError,
    state.playbooks,
  ]);

  const pluginsLoading =
    analyzersLoading ||
    connectorsLoading ||
    visualizersLoading ||
    pivotsLoading;

  const selectObservableType = (value) => {
    formik.setFieldValue("observableType", value, false);
    formik.setFieldValue(
      "classification",
      value === JobTypes.OBSERVABLE
        ? ObservableClassifications.GENERIC
        : JobTypes.FILE,
    );
    formik.setFieldValue("observable_names", [""], false);
    formik.setFieldValue("files", [""], false);
    formik.setFieldValue("analysisOptionValues", ScanTypes.playbooks, false);
    setScanType(ScanTypes.playbooks);
    formik.setFieldValue("playbook", "", false); // reset
    formik.setFieldValue("analyzers", [], false); // reset
    formik.setFieldValue("connectors", [], false); // reset
  };

  const updateAdvancedConfig = (
    tags,
    tlp,
    _scanMode,
    scanCheckTime,
    runtimeConfiguration,
  ) => {
    formik.setFieldValue("tags", tags, false);
    formik.setFieldValue("tlp", tlp, false);
    formik.setFieldValue("scan_mode", _scanMode, false);
    // null for playbooks with force new
    console.debug(`scanCheckTime : ${scanCheckTime}`);
    if (scanCheckTime) {
      formik.setFieldValue(
        "scan_check_time",
        parseScanCheckTime(scanCheckTime),
        false,
      );
    }
    formik.setFieldValue("runtime_configuration", runtimeConfiguration, false);
  };

  const updateSelectedPlaybook = (playbook) => {
    formik.setFieldValue("playbook", playbook, false);
    updateAdvancedConfig(
      playbook.tags,
      playbook.tlp,
      playbook.scan_mode,
      playbook.scan_check_time,
      playbook.runtime_configuration,
    );
  };

  // wait the user terminated to typing and then perform the request to recent scans
  useDebounceInput(inputValue, 1000, setRecentScansInput);

  const updateSelectedObservable = (observableValue, index) => {
    if (index === 0) {
      const oldClassification = formik.values.classification;
      const newClassification = getObservableClassification(observableValue);
      formik.setFieldValue("classification", newClassification, false);
      // in case a playbook is available and i changed classification or no playbook is selected i select a playbook
      if (
        playbookOptions(playbooks, newClassification, organizationPluginsState)
          .length > 0 &&
        (oldClassification !== newClassification ||
          Object.keys(formik.values.playbook).length === 0) &&
        formik.values.analysisOptionValues === ScanTypes.playbooks
      ) {
        updateSelectedPlaybook(
          playbookOptions(
            playbooks,
            newClassification,
            organizationPluginsState,
          )[0],
        );
      }
    }
    const observableNames = formik.values.observable_names;
    observableNames[index] = observableValue;
    formik.setFieldValue("observable_names", observableNames, false);
    setInputValue(observableValue);
  };

  const [scanType, setScanType] = React.useState(
    formik.values.analysisOptionValues,
  );

  const updateAnalysisOptionValues = (newAnalysisType) => {
    if (
      scanType === ScanTypes.playbooks &&
      newAnalysisType === ScanTypes.analyzers_and_connectors
    ) {
      setScanType(newAnalysisType);
      // reset playbook
      formik.setFieldValue("playbook", formik.initialValues.playbook, false);
      // reset advanced configuration
      updateAdvancedConfig(
        formik.initialValues.tags,
        formik.initialValues.tlp,
        formik.initialValues.scan_mode,
        "01:00:00:00",
        formik.initialValues.runtime_configuration,
      );
    }
    if (
      scanType === ScanTypes.analyzers_and_connectors &&
      newAnalysisType === ScanTypes.playbooks
    ) {
      setScanType(newAnalysisType);
      // if an observable or file is loaded set a default playbook
      if (
        (formik.values.observable_names.length &&
          formik.values.observable_names[0] !== "") ||
        (formik.values.files.length &&
          formik.values.files[0] !== "" &&
          Object.keys(formik.values.playbook).length === 0)
      ) {
        updateSelectedPlaybook(
          playbookOptions(
            playbooks,
            formik.values.classification,
            organizationPluginsState,
          )[0],
        );
        formik.setFieldValue("analyzers", [], false); // reset
        formik.setFieldValue("connectors", [], false); // reset
      }
    }
  };

  // useEffect for setting the default playbook if an observable or a file is loaded before playbooks are fetched
  useEffect(() => {
    if (
      (formik.values.observable_names.length &&
        formik.values.observable_names[0] !== "") ||
      (formik.values.files.length &&
        formik.values.files[0] !== "" &&
        Object.keys(formik.values.playbook).length === 0 &&
        formik.values.analysisOptionValues === ScanTypes.playbooks)
    ) {
      updateSelectedPlaybook(
        playbookOptions(
          playbooks,
          formik.values.classification,
          organizationPluginsState,
        )[0],
      );
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [playbooksLoading]);

  useEffect(() => {
    if (observableParam) {
      updateSelectedObservable(observableParam, 0);
      if (formik.playbook) updateSelectedPlaybook(formik.playbook);
    } else if (isSampleParam) {
      selectObservableType(JobTypes.FILE);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [observableParam, playbooksLoading, isSampleParam]);

  /* With the setFieldValue the validation and rerender don't work properly: the last update seems to not trigger the validation
  and leaves the UI with values not valid, for this reason the scan button is disabled, but if the user set focus on the UI the last
  validation trigger and start scan is enabled. To avoid this we use this hook that force the validation when the form values change.
  
  This hook is the reason why we can disable the validation in the setFieldValue method (3rd params).
  */
  React.useEffect(() => {
    formik.validateForm();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [formik.values]);

  const [isRuntimeConfigModalOpen, setRuntimeConfigModalOpen] =
    React.useState(false);
  const toggleRuntimeConfigModal = () => {
    if (!pluginsLoading) setRuntimeConfigModalOpen((open) => !open);
  };
  const [isMultipleObservablesModalOpen, setMultipleObservablesModalOpen] =
    React.useState(false);
  const toggleMultipleObservablesModal = React.useCallback(
    () => setMultipleObservablesModalOpen((open) => !open),
    [setMultipleObservablesModalOpen],
  );

  // useEffect for setting the default playbook if multiple observables are loaded
  useEffect(() => {
    if (
      formik.values.observable_names.length &&
      formik.values.observable_names[0] !== ""
    ) {
      formik.values.observable_names.forEach((observable, index) =>
        updateSelectedObservable(observable, index),
      );
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [toggleMultipleObservablesModal, formik.values.observable_names]);

  console.debug(`classification: ${formik.values.classification}`);
  console.debug("formik");
  console.debug(formik);
  return (
    <Container fluid className="d-flex justify-content-center">
      {/* Form */}
      <ContentSection
        id="ScanForm"
        className="col-lg-8 col-xl-7 mt-3 bg-body shadow"
      >
        <div className="mt-4 d-flex justify-content-between">
          <h3 id="scanpage" className="fw-bold">
            Scan&nbsp;
            {formik.values.classification === JobTypes.FILE
              ? "Files"
              : "Observables"}
          </h3>
          <div className="mt-1">
            {/* Quota badges */}
            <MonthBadge className="me-2 text-larger" />
            <TotalBadge className="ms-2 me-3 text-larger" />
            <QuotaInfoIcon />
          </div>
        </div>
        <hr />
        <FormikProvider value={formik}>
          <Form onSubmit={formik.handleSubmit}>
            <Row>
              <div className="col-sm-3 col-form-label" />
              <FormGroup className="ps-3 mt-2 d-flex col-sm-8">
                {[JobTypes.OBSERVABLE, JobTypes.FILE].map((jobType) => (
                  <FormGroup check inline key={`observableType__${jobType}`}>
                    <Col>
                      <Field
                        as={Input}
                        id={`observableType__${jobType}`}
                        type="radio"
                        name="observableType"
                        value={jobType}
                        onClick={(event) =>
                          selectObservableType(event.target.value)
                        }
                      />
                      <Label check>
                        {jobType === JobTypes.OBSERVABLE
                          ? "observable (domain, IP, URL, HASH, etc...)"
                          : "file"}
                      </Label>
                    </Col>
                  </FormGroup>
                ))}
              </FormGroup>
              <Col sm={1} className="d-flex-center justify-content-end mb-3">
                {formik.values.classification !== "file" && (
                  <IconButton
                    id="scanform-multipleobservables-btn"
                    Icon={RiFileAddLine}
                    title="Load multilple observables"
                    titlePlacement="top"
                    size="sm"
                    color="tertiary"
                    onClick={toggleMultipleObservablesModal}
                  />
                )}
                {isMultipleObservablesModalOpen && (
                  <MultipleObservablesModal
                    isOpen={isMultipleObservablesModalOpen}
                    toggle={toggleMultipleObservablesModal}
                    formik={formik}
                  />
                )}
              </Col>
            </Row>
            {formik.values.observableType === JobTypes.OBSERVABLE ? (
              <FieldArray
                name="observable_names"
                render={(arrayHelpers) => (
                  <FormGroup row>
                    <Label
                      id="selectobservable"
                      className="required"
                      sm={3}
                      for="observable_name"
                    >
                      Observable Value(s)
                    </Label>
                    <Col sm={9}>
                      <div className="invalid-feedback d-block">
                        {formik.errors.no_observables}
                      </div>
                      <div style={{ maxHeight: "27vh", overflowY: "scroll" }}>
                        {formik.values.observable_names &&
                        formik.values.observable_names.length > 0
                          ? formik.values.observable_names.map(
                              (name, index) => (
                                <div
                                  className="py-2 d-flex"
                                  key={`observable_names.${index + 0}`}
                                >
                                  <Col sm={11} className="ps-1 pe-3">
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
                                            formik.errors.observable_names[
                                              index
                                            ],
                                        ) &&
                                        formik.touched.observable_names &&
                                        formik.touched.observable_names[index]
                                      }
                                      onChange={(event) =>
                                        updateSelectedObservable(
                                          event.target.value,
                                          index,
                                        )
                                      }
                                    />
                                    {DangerErrorMessage("observable_names")}
                                  </Col>
                                  <Button
                                    color="primary"
                                    className="mx-auto rounded-1 text-larger col-sm-1"
                                    onClick={() => arrayHelpers.remove(index)}
                                  >
                                    <BsFillTrashFill />
                                  </Button>
                                </div>
                              ),
                            )
                          : null}
                      </div>
                      <Row className="my-2 pt-0">
                        <Button
                          color="primary"
                          size="sm"
                          className="mx-auto rounded-1 mx-auto col-sm-auto d-flex align-items-center"
                          onClick={() => arrayHelpers.push("")}
                        >
                          <BsFillPlusCircleFill />
                          &nbsp;Add new value
                        </Button>
                      </Row>
                    </Col>
                  </FormGroup>
                )}
              />
            ) : (
              <FormGroup row>
                <Label className="required" sm={3} for="file">
                  File(s)
                </Label>
                <Col sm={9}>
                  <Input
                    type="file"
                    id="file"
                    name="file"
                    onChange={(event) => {
                      formik.setFieldValue(
                        "files",
                        event.currentTarget.files,
                        false,
                      );
                      formik.setFieldValue("classification", "file", false);
                      if (
                        Object.keys(formik.values.playbook).length === 0 &&
                        playbookOptions(
                          playbooks,
                          "file",
                          organizationPluginsState,
                        ).length > 0 &&
                        formik.values.analysisOptionValues ===
                          ScanTypes.playbooks
                      ) {
                        updateSelectedPlaybook(
                          playbookOptions(
                            playbooks,
                            "file",
                            organizationPluginsState,
                          )[0],
                        );
                      }
                    }}
                    className="input-dark"
                    multiple
                  />
                  {DangerErrorMessage("files")}
                </Col>
              </FormGroup>
            )}
            <hr />
            <Row>
              <div className="col-sm-3 col-form-label mb-3" />
              <FormGroup className="d-flex col-sm-8 align-items-center">
                {Object.values(ScanTypes).map((type_) => (
                  <FormGroup check inline key={`analysistype__${type_}`}>
                    <Col>
                      <Field
                        as={Input}
                        id={`analysistype__${type_}`}
                        type="radio"
                        name="analysisOptionValues"
                        value={type_}
                        onClick={() => updateAnalysisOptionValues(type_)}
                      />
                      <Label check>{type_}</Label>
                    </Col>
                  </FormGroup>
                ))}
              </FormGroup>
              <Col sm={1} className="d-flex-center justify-content-end mb-3">
                <IconButton
                  id="scanform-runtimeconf-editbtn"
                  Icon={
                    pluginsLoading &&
                    (formik.values.analyzers.length > 0 ||
                      formik.values.connectors.length > 0 ||
                      Object.keys(formik.values.playbook).length > 0)
                      ? SpinnerIcon
                      : MdEdit
                  }
                  title={
                    pluginsLoading
                      ? "Runtime configuration is loading"
                      : "Edit runtime configuration"
                  }
                  titlePlacement="top"
                  size="sm"
                  color="tertiary"
                  disabled={
                    !(
                      formik.values.analyzers.length > 0 ||
                      formik.values.connectors.length > 0 ||
                      Object.keys(formik.values.playbook).length > 0
                    )
                  }
                  onClick={toggleRuntimeConfigModal}
                />
                {isRuntimeConfigModalOpen && (
                  <RuntimeConfigurationModal
                    isOpen={isRuntimeConfigModalOpen}
                    toggle={toggleRuntimeConfigModal}
                    formik={formik}
                  />
                )}
              </Col>
            </Row>
            {scanType === ScanTypes.analyzers_and_connectors && (
              <>
                <FormGroup row>
                  <Label sm={3} for="analyzers">
                    Select Analyzers
                  </Label>
                  <Col sm={9}>
                    <AnalyzersMultiSelectDropdownInput formik={formik} />
                    {DangerErrorMessage("analyzers")}
                  </Col>
                </FormGroup>
                <FormGroup row>
                  <Label sm={3} for="connectors">
                    Select Connectors
                  </Label>
                  <Col sm={9}>
                    <ConnectorsMultiSelectDropdownInput formik={formik} />
                  </Col>
                </FormGroup>
              </>
            )}
            {scanType === ScanTypes.playbooks && (
              <FormGroup row className="mb-4">
                <Label id="selectplugins" sm={3} htmlFor="playbook">
                  Select Playbook
                </Label>
                <Col sm={9}>
                  <PlaybookMultiSelectDropdownInput
                    formik={formik}
                    onChange={(selectedPlaybook) =>
                      updateSelectedPlaybook(selectedPlaybook)
                    }
                  />
                  {DangerErrorMessage("playbook")}
                </Col>
              </FormGroup>
            )}
            <FormGroup row>
              <TLPSelectInputLabel size={3} />
              <Col sm={9}>
                <TLPSelectInput formik={formik} />
              </Col>
            </FormGroup>
            <hr />
            <Button
              size="sm"
              onClick={() => toggleAdvancedSettings(!isAdvancedSettingsOpen)}
              color="primary"
              className="mt-2"
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
                    setSelectedTags={(selectedTags) =>
                      formik.setFieldValue("tags", selectedTags, false)
                    }
                  />
                </Col>
              </FormGroup>
              <FormGroup row className="mt-2">
                <Label sm={3}>Scan configuration</Label>
                <Col sm={9}>
                  <ScanConfigSelectInput formik={formik} />
                </Col>
              </FormGroup>
            </Collapse>

            <FormGroup row className="mt-3">
              <Button
                id="startScan"
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
                className="mx-auto rounded-0 col-sm-3 order-sm-5"
              >
                {formik.isSubmitting && <Spinner size="sm" />}Start Scan
              </Button>
            </FormGroup>
          </Form>
        </FormikProvider>
      </ContentSection>
      {/* Recent Scans */}
      <ContentSection
        id="RecentScans"
        className="col-lg-4 col-xl-4 mt-3 mx-3 bg-body shadow"
      >
        <RecentScans
          classification={formik.values.classification}
          param={
            formik.values.files.length
              ? formik.values.files[0]
              : sanitizeObservable(recentScansInput)
          }
        />
      </ContentSection>
    </Container>
  );
}
