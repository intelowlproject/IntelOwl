/* eslint-disable react/prop-types */
import React, { useEffect } from "react";
import { useFormik, Form, FormikProvider } from "formik";
import {
  Container,
  Row,
  Col,
  Input,
  Label,
  UncontrolledTooltip,
  Button,
  Spinner,
} from "reactstrap";
import { Link } from "react-router-dom";
import { MdInfoOutline } from "react-icons/md";
import { Loader, DataTable } from "@certego/certego-ui";

import { format } from "date-fns";
import { PluginsTypes, PluginFinalStatuses } from "../../constants/pluginConst";
import { searchTableColumns } from "./searchTableColumns";
import { pluginReportQueries } from "./searchApi";
import { useJsonEditorStore } from "../../stores/useJsonEditorStore";
import { SearchJSONReport } from "./utils";

import { datetimeFormatStr } from "../../constants/miscConst";
import { INTELOWL_DOCS_URL } from "../../constants/environment";

// table config
const tableConfig = { enableExpanded: true, enableFlexLayout: true };
const tableInitialState = {
  pageSize: 10,
  sortBy: [{ id: "end_time", desc: false }],
};

const tableProps = {
  SubComponent: ({ row }) => <SearchJSONReport row={row} />,
};

export default function ReportsSearch() {
  const [elasticData, setElasticData] = React.useState([]);
  const [loadingData, setLoadingData] = React.useState(false);
  const [setTextToHighlight] = useJsonEditorStore((state) => [
    state.setTextToHighlight,
  ]);

  const defaultStartDate = new Date();
  defaultStartDate.setDate(defaultStartDate.getDate() - 30); // default: 30 days time range
  const defaultStartDateStr = format(defaultStartDate, datetimeFormatStr);

  const formik = useFormik({
    initialValues: {
      type: "",
      name: "",
      status: "",
      fromStartTime: defaultStartDateStr,
      toStartTime: format(new Date(), datetimeFormatStr),
      fromEndTime: defaultStartDateStr,
      toEndTime: format(new Date(), datetimeFormatStr),
      errors: "",
      report: "",
    },
    validate: (values) => {
      console.debug("validate - values");
      console.debug(values);
      const errors = {};

      if (Date.parse(values.toStartTime) < Date.parse(values.fromStartTime)) {
        errors.startTime = "Start date must be equal or lower than end date";
      }
      if (Date.parse(values.toEndTime) < Date.parse(values.fromEndTime)) {
        errors.endTime = "Start date must be equal or lower than end date";
      }
      console.debug("formik validation errors");
      console.debug(errors);
      return errors;
    },
    onSubmit: async () => {
      const queryParams = {
        start_start_time: new Date(formik.values.fromStartTime),
        end_start_time: new Date(formik.values.toStartTime),
        start_end_time: new Date(formik.values.fromEndTime),
        end_end_time: new Date(formik.values.toEndTime),
      };
      Object.entries(formik.values).forEach(([key, value]) => {
        if (formik.initialValues[key] !== value)
          if (key === "type") queryParams.plugin_name = value;
          else if (key === "fromStartTime")
            queryParams.start_start_time = new Date(value);
          else if (key === "toStartTime")
            queryParams.end_start_time = new Date(value);
          else if (key === "fromEndTime")
            queryParams.start_end_time = new Date(value);
          else if (key === "toEndTime")
            queryParams.end_end_time = new Date(value);
          else queryParams[key] = value;
      });

      let response = [];
      try {
        setLoadingData(true);
        response = await pluginReportQueries(
          queryParams,
          tableInitialState.pageSize,
          20,
        );
      } catch (err) {
        // error will be handled by pluginReportQueries
      } finally {
        setLoadingData(false);
        setElasticData(response);
        formik.setSubmitting(false);
      }
    },
  });

  useEffect(() => {
    // this hook is required to run a request when the page is visited the first time
    formik.handleSubmit();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <Container fluid className="overflow-hidden">
      <FormikProvider value={formik}>
        <Form onSubmit={formik.handleSubmit}>
          <Row className="mb-2">
            <Col className="d-flex align-items-center">
              <h1 id="reportSearch">
                Reports Search&nbsp;
                <small className="text-gray" style={{ marginBottom: "0.5rem" }}>
                  {elasticData?.length} total
                </small>
              </h1>
              <div className="ms-2">
                <MdInfoOutline id="search__elastic-infoicon" fontSize="20" />
                <UncontrolledTooltip
                  trigger="hover"
                  delay={{ show: 0, hide: 200 }}
                  target="search__elastic-infoicon"
                  placement="right"
                  fade={false}
                  innerClassName="p-2 text-start text-nowrap md-fit-content"
                >
                  This section only works if Elasticsearch has been configured
                  correctly. For more info check the{" "}
                  <Link
                    to={`${INTELOWL_DOCS_URL}IntelOwl/advanced_configuration/#elasticsearch`}
                    target="_blank"
                  >
                    official doc.
                  </Link>
                </UncontrolledTooltip>
              </div>
            </Col>
            <span style={{ marginBottom: "0.5rem" }}>
              Advanced search in plugin reports of the performed analysis.
            </span>
          </Row>
          <Row id="search-input-fields-first-row d-flex flex-wrap">
            <Col xxl={4} sm={12} className="d-flex align-items-center mt-4">
              <Label className="col-3 fw-bold mb-0" for="search__type">
                Type:
              </Label>
              <Input
                id="search__type"
                type="select"
                name="type"
                value={formik.values.type}
                onBlur={formik.handleBlur}
                onChange={formik.handleChange}
                className="bg-darker border-dark"
              >
                <option value="">Select...</option>
                {[
                  PluginsTypes.ANALYZER,
                  PluginsTypes.CONNECTOR,
                  PluginsTypes.PIVOT,
                ]
                  .sort()
                  .map((value) => (
                    <option
                      key={`search__type-select-option-${value}`}
                      value={value}
                    >
                      {value.toUpperCase()}
                    </option>
                  ))}
              </Input>
            </Col>
            <Col xxl={4} sm={12} className="d-flex align-items-center mt-4">
              <Label className="col-3 fw-bold mb-0" for="search__name">
                Name:
              </Label>
              <Input
                id="search__name"
                type="text"
                name="name"
                placeholder="Enter a plugin name"
                value={formik.values.name}
                onBlur={formik.handleBlur}
                onChange={formik.handleChange}
                className="col bg-darker border-dark"
              />
            </Col>
            <Col xxl={3} sm={12} className=" d-flex align-items-center mt-4">
              <Label
                className="col-xxl-4 col-sm-3 fw-bold mb-0"
                for="search__status"
              >
                Status:
              </Label>
              <Input
                id="search__status"
                type="select"
                name="status"
                value={formik.values.status}
                onBlur={formik.handleBlur}
                onChange={formik.handleChange}
                className="col bg-darker border-dark"
              >
                <option value="">Select...</option>
                {Object.values(PluginFinalStatuses).map((value) => (
                  <option
                    key={`search__status-select-option-${value}`}
                    value={value}
                  >
                    {value}
                  </option>
                ))}
              </Input>
            </Col>
          </Row>
          <Row
            id="search-input-fields-second-row"
            className="flex-wrap overflow-hidden g-0"
          >
            <Col
              xl={6}
              lg={12}
              className="d-flex align-items-start flex-wrap mt-3 pe-2"
              style={{ maxWidth: "100%", overflow: "hidden" }}
            >
              <Label className="col-12 col-lg-3 fw-bold mb-2 mb-lg-0">
                Start time:
              </Label>
              <div
                className="col-12 col-lg-9 d-flex flex-column align-item-start"
                style={{ minWidth: 0, maxWidth: "100%" }}
              >
                <div className="d-flex flex-column flex-wrap w-100">
                  <div className="d-flex align-items-center mb-1 flex-wrap w-100">
                    <Label
                      className="col-12 col-sm-auto mb-0 mb-sm-0 mb-1 me-2"
                      for="search__fromStartTime"
                      style={{ minWidth: "fit-content" }}
                    >
                      from
                    </Label>
                    <div
                      className="col-12 col-sm flex-grow-1"
                      style={{ minWidth: 0, maxWidth: "100%" }}
                    >
                      <Input
                        id="search__fromStartTime"
                        type="datetime-local"
                        name="fromStartTime"
                        autoComplete="off"
                        value={formik.values.fromStartTime}
                        onBlur={formik.handleBlur}
                        onChange={formik.handleChange}
                        invalid={formik.errors.startTime}
                        className="bg-darker border-dark"
                        style={{ width: "100%", maxWidth: "100%", minWidth: 0 }}
                      />
                    </div>
                  </div>
                  <div className="d-flex align-items-center flex-wrap w-100">
                    <Label
                      className="col-12 col-sm-auto mb-0 mb-sm-0 mb-1 me-2"
                      for="search__toStartTime"
                      style={{ minWidth: "fit-content" }}
                    >
                      to
                    </Label>
                    <div
                      className="col-12 col-sm flex-grow-1"
                      style={{ minWidth: 0, maxWidth: "100%" }}
                    >
                      <Input
                        id="search__toStartTime"
                        type="datetime-local"
                        name="toStartTime"
                        autoComplete="off"
                        value={formik.values.toStartTime}
                        onBlur={formik.handleBlur}
                        onChange={formik.handleChange}
                        invalid={formik.errors.startTime}
                        className="bg-darker border-dark"
                        style={{ width: "100%", maxWidth: "100%", minWidth: 0 }}
                      />
                    </div>
                  </div>
                </div>
                {formik.errors.startTime && (
                  <small className="text-danger">
                    {formik.errors.startTime}
                  </small>
                )}
              </div>
            </Col>
            <Col
              xl={6}
              lg={12}
              className="d-flex align-items-start flex-wrap mt-3 pe-2"
              style={{ maxWidth: "100%", overflow: "hidden" }}
            >
              <Label className="col-12 col-lg-3 fw-bold mb-2 mb-lg-0">
                End time:
              </Label>
              <div
                className="col-12 col-lg-9 d-flex flex-column align-item-start"
                style={{ minWidth: 0, maxWidth: "100%" }}
              >
                <div className="d-flex flex-column flex-wrap w-100">
                  <div className="d-flex align-items-center mb-1 flex-wrap w-100">
                    <Label
                      className="col-12 col-sm-auto mb-0 mb-sm-0 mb-1 me-2"
                      for="search__fromEndTime"
                      style={{ minWidth: "fit-content" }}
                    >
                      from
                    </Label>
                    <div
                      className="col-12 col-sm flex-grow-1"
                      style={{ minWidth: 0, maxWidth: "100%" }}
                    >
                      <Input
                        id="search__fromEndTime"
                        type="datetime-local"
                        name="fromEndTime"
                        autoComplete="off"
                        value={formik.values.fromEndTime}
                        onBlur={formik.handleBlur}
                        onChange={formik.handleChange}
                        invalid={formik.errors.endTime}
                        className="bg-darker border-dark"
                        style={{ width: "100%", maxWidth: "100%", minWidth: 0 }}
                      />
                    </div>
                  </div>
                  <div className="d-flex align-items-center flex-wrap w-100">
                    <Label
                      className="col-12 col-sm-auto mb-0 mb-sm-0 mb-1 me-2"
                      for="search__toEndTime"
                      style={{ minWidth: "fit-content" }}
                    >
                      to
                    </Label>
                    <div
                      className="col-12 col-sm flex-grow-1"
                      style={{ minWidth: 0, maxWidth: "100%" }}
                    >
                      <Input
                        id="search__toEndTime"
                        type="datetime-local"
                        name="toEndTime"
                        autoComplete="off"
                        value={formik.values.toEndTime}
                        onBlur={formik.handleBlur}
                        onChange={formik.handleChange}
                        invalid={formik.errors.endTime}
                        className="bg-darker border-dark"
                        style={{ width: "100%", maxWidth: "100%", minWidth: 0 }}
                      />
                    </div>
                  </div>
                </div>
                {formik.errors.endTime && (
                  <small className="text-danger">{formik.errors.endTime}</small>
                )}
              </div>
            </Col>
            <Col xl={12} lg={12} className="d-flex align-items-center mt-3">
              <Label
                className="col-xxl-4 col-sm-3 fw-bold mb-0"
                for="search__errors"
              >
                Errors:
              </Label>
              <Input
                id="search__errors"
                type="select"
                name="errors"
                value={formik.values.errors}
                onBlur={formik.handleBlur}
                onChange={formik.handleChange}
                className="bg-darker border-dark"
              >
                <option value="">Select...</option>
                {[
                  { value: true, label: "Reports with errors" },
                  { value: false, label: "Reports without errors" },
                ]
                  .sort()
                  .map((option) => (
                    <option
                      key={`search__errors-select-option-${option.value}`}
                      value={option.value}
                    >
                      {option.label}
                    </option>
                  ))}
              </Input>
            </Col>
          </Row>
          <Row id="search-input-fields-third-row">
            <Col xxl={11} sm={12} className="d-flex align-items-center mt-3">
              <Label
                className="col-xxl-1 col-sm-3 fw-bold mb-0"
                for="search__report"
              >
                Text search:
                <MdInfoOutline
                  id="search__report-infoicon"
                  fontSize="20"
                  className="ms-2"
                />
                <UncontrolledTooltip
                  trigger="hover"
                  delay={{ show: 0, hide: 200 }}
                  target="search__report-infoicon"
                  placement="right"
                  fade={false}
                  innerClassName="p-2 text-start text-nowrap md-fit-content"
                >
                  Text field to search within the “report“ and therefore in the
                  data extracted from the plugins.
                </UncontrolledTooltip>
              </Label>
              <Input
                id="search__report"
                type="text"
                name="report"
                value={formik.values.report}
                onChange={(event) => {
                  formik.setFieldValue("report", event.target.value, false);
                  setTextToHighlight(event.target.value);
                }}
                onBlur={formik.handleBlur}
                className="bg-darker border-dark"
                invalid={formik.touched.report && formik.errors.report}
              />
            </Col>
            <Col
              xxl={1}
              sm={12}
              className="d-flex align-items-center justify-content-end mt-3"
            >
              <Button
                id="search-button"
                className="d-flex align-items-center"
                size="sm"
                color="primary"
                type="submit"
                disabled={!formik.isValid || formik.isSubmitting}
              >
                {formik.isSubmitting && <Spinner size="sm" />}Search
              </Button>
            </Col>
          </Row>
        </Form>
      </FormikProvider>
      <Row className="mt-4">
        <Loader
          loading={loadingData}
          render={() => (
            <DataTable
              data={elasticData}
              config={tableConfig}
              initialState={tableInitialState}
              columns={searchTableColumns}
              autoResetPage
              {...tableProps}
            />
          )}
        />
      </Row>
    </Container>
  );
}
