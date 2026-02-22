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
  Alert,
} from "reactstrap";
import { Link } from "react-router-dom";
import { MdInfoOutline } from "react-icons/md";
import { Loader, DataTable, selectStyles } from "@certego/certego-ui";
import ReactSelect from "react-select";

import { format } from "date-fns";
import { PluginsTypes, PluginFinalStatuses } from "../../constants/pluginConst";
import { searchTableColumns } from "./searchTableColumns";
import { pluginReportQueries } from "./searchApi";
import { useJsonEditorStore } from "../../stores/useJsonEditorStore";
import { usePluginConfigurationStore } from "../../stores/usePluginConfigurationStore";
import { SearchJSONReport } from "./utils";

import { datetimeFormatStr } from "../../constants/miscConst";
import { INTELOWL_DOCS_URL } from "../../constants/environment";

// table config
const tableConfig = {
  enableExpanded: true,
  enableFlexLayout: true,
  enableFilters: true,
};
const tableInitialState = {
  pageSize: 10,
  sortBy: [{ id: "end_time", desc: false }],
};

const tableProps = {
  // @ts-ignore - row is provided by DataTable
  SubComponent: ({ row }) => <SearchJSONReport row={row} />,
};

export default function ReportsSearch() {
  const [elasticData, setElasticData] = React.useState([]);
  const [loadingData, setLoadingData] = React.useState(false);
  const [totalCount, setTotalCount] = React.useState(0);
  const [currentPage, setCurrentPage] = React.useState(1);
  const [queryParams, setQueryParams] = React.useState({});
  const [error, setError] = React.useState(null);
  const [setTextToHighlight] = useJsonEditorStore((state) => [
    state.setTextToHighlight,
  ]);
  
  // Get plugins from store  
  const [analyzers, connectors, pivots] = usePluginConfigurationStore(
    (state) => [state.analyzers, state.connectors, state.pivots],
  );
  
  // Create options for plugin name dropdown
  const pluginNameOptions = React.useMemo(() => {
    const allPlugins = [
      // @ts-ignore - plugin object structure
      ...analyzers.map((plugin) => ({ ...plugin, type: PluginsTypes.ANALYZER })),
      // @ts-ignore - plugin object structure
      ...connectors.map((plugin) => ({ ...plugin, type: PluginsTypes.CONNECTOR })),
      // @ts-ignore - plugin object structure
      ...pivots.map((plugin) => ({ ...plugin, type: PluginsTypes.PIVOT })),
    ];
    
    return allPlugins
      .map((plugin) => ({
        value: plugin.name,
        label: `${plugin.name} (${plugin.type})`,
      }))
      .sort((optionA, optionB) => optionA.value.localeCompare(optionB.value));
  }, [analyzers, connectors, pivots]);

  const defaultStartDate = new Date();
  defaultStartDate.setDate(defaultStartDate.getDate() - 30); // default: 30 days time range
  const defaultStartDateStr = format(defaultStartDate, datetimeFormatStr);

  // Read URL parameters on mount
  const getInitialValues = () => {
    const urlParams = new URLSearchParams(window.location.search);
    return {
      type: urlParams.get("type") || "",
      name: urlParams.get("name") || "",
      status: urlParams.get("status") || "",
      fromStartTime: urlParams.get("fromStartTime") || defaultStartDateStr,
      toStartTime: urlParams.get("toStartTime") || format(new Date(), datetimeFormatStr),
      fromEndTime: urlParams.get("fromEndTime") || defaultStartDateStr,
      toEndTime: urlParams.get("toEndTime") || format(new Date(), datetimeFormatStr),
      errors: urlParams.get("errors") || "",
      report: urlParams.get("report") || "",
    };
  };

  const formik = useFormik({
    initialValues: getInitialValues(),
    validate: (values) => {
      console.debug("validate - values");
      console.debug(values);
      const errors = {};

      if (Date.parse(values.toStartTime) < Date.parse(values.fromStartTime)) {
        errors.fromStartTime = "Start date must be equal or lower than end date";
      }
      if (Date.parse(values.toEndTime) < Date.parse(values.fromEndTime)) {
        errors.fromEndTime = "Start date must be equal or lower than end date";
      }
      console.debug("formik validation errors");
      console.debug(errors);
      return errors;
    },
    onSubmit: async () => {
      const params = {
        start_start_time: new Date(formik.values.fromStartTime),
        end_start_time: new Date(formik.values.toStartTime),
        start_end_time: new Date(formik.values.fromEndTime),
        end_end_time: new Date(formik.values.toEndTime),
      };
      
      Object.entries(formik.values).forEach(([key, value]) => {
        // @ts-ignore - dynamic property access
        const initialValue = formik.initialValues[key];
        if (initialValue !== value) {
          // @ts-ignore - dynamic property assignment
          if (key === "type") params.plugin_name = value;
          else if (key === "fromStartTime")
            params.start_start_time = new Date(value);
          else if (key === "toStartTime")
            params.end_start_time = new Date(value);
          else if (key === "fromEndTime")
            params.start_end_time = new Date(value);
          else if (key === "toEndTime")
            params.end_end_time = new Date(value);
          // @ts-ignore - dynamic property assignment
          else params[key] = value;
        }
      });

      setQueryParams(params);
      setCurrentPage(1);
      
      try {
        setLoadingData(true);
        setError(null);
        const response = await pluginReportQueries(
          params,
          tableInitialState.pageSize,
          1,
        );
        setElasticData(response.results);
        setTotalCount(response.count);
      } catch (err) {
        console.error("Search query failed:", err);
        // @ts-ignore - error can be string or null
        setError("Failed to load search results. Please try again.");
        // Keep existing data on error instead of clearing it
      } finally {
        setLoadingData(false);
        formik.setSubmitting(false);
      }
    },
  });

  // Update URL when form values change
  useEffect(() => {
    const urlParams = new URLSearchParams();
    Object.entries(formik.values).forEach(([key, value]) => {
      // Skip empty values and datetime fields that are still at defaults
      if (value && value !== "") {
        urlParams.set(key, value);
      }
    });
    const newUrl = `${window.location.pathname}${urlParams.toString() ? `?${urlParams.toString()}` : ""}`;
    window.history.replaceState({}, "", newUrl);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [formik.values]);

  useEffect(() => {
    // this hook is required to run a request when the page is visited the first time
    formik.handleSubmit();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Handle pagination
  /** @param {number} newPageIndex */
  const handlePageChange = async (newPageIndex) => {
    const pageNumber = newPageIndex + 1;
    if (pageNumber === currentPage) return;
    
    setCurrentPage(pageNumber);
    setLoadingData(true);
    setError(null);
    
    try {
      const response = await pluginReportQueries(
        queryParams,
        tableInitialState.pageSize,
        pageNumber,
      );
      setElasticData(response.results);
      setTotalCount(response.count);
    } catch (err) {
      console.error(`Failed to load page ${pageNumber}:`, err);
      // @ts-ignore - error can be string or null
      setError(`Failed to load page ${pageNumber}. Please try again.`);
      // Revert to previous page on error
      setCurrentPage(currentPage);
    } finally {
      setLoadingData(false);
    }
  };

  return (
    <Container fluid>
      <FormikProvider value={formik}>
        <Form onSubmit={formik.handleSubmit}>
          <Row className="mb-2">
            <Col className="d-flex align-items-center">
              <h1 id="reportSearch">
                Reports Search&nbsp;
                <small className="text-gray" style={{ marginBottom: "0.5rem" }}>
                  {totalCount} total
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
              <div className="col">
                <ReactSelect
                  id="search__name"
                  name="name"
                  options={pluginNameOptions}
                  value={
                    formik.values.name
                      ? pluginNameOptions.find(
                          (opt) => opt.value === formik.values.name,
                        ) || null
                      : null
                  }
                  onChange={(selected) =>
                    formik.setFieldValue(
                      "name",
                      selected ? selected.value : "",
                      false,
                    )
                  }
                  onBlur={() => formik.setFieldTouched("name", true)}
                  isClearable
                  placeholder="Search and select a plugin..."
                  styles={selectStyles}
                  classNamePrefix="react-select"
                />
              </div>
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
          <Row id="search-input-fields-second-row">
            <Col
              xxl={4}
              sm={12}
              className="d-flex align-items-center flex-wrap mt-3"
            >
              <Label className="col-3 fw-bold mb-0">
                Start time:
                <MdInfoOutline
                  id="search__starttime-infoicon"
                  fontSize="16"
                  className="ms-1"
                />
                <UncontrolledTooltip
                  trigger="hover"
                  delay={{ show: 0, hide: 200 }}
                  target="search__starttime-infoicon"
                  placement="right"
                  fade={false}
                  innerClassName="p-2 text-start text-nowrap md-fit-content"
                >
                  Format: YYYY-MM-DDTHH:MM (e.g., 2024-01-15T14:30)
                </UncontrolledTooltip>
              </Label>
              <div className="d-flex flex-column align-item-start">
                <div className="d-flex flex-column flex-wrap">
                  <div className="d-flex align-items-center mb-1">
                    <Label className="col-3 mb-0" for="search__fromStartTime">
                      from
                    </Label>
                    <Input
                      id="search__fromStartTime"
                      type="datetime-local"
                      name="fromStartTime"
                      autoComplete="off"
                      value={formik.values.fromStartTime}
                      onBlur={formik.handleBlur}
                      onChange={formik.handleChange}
                      onKeyDown={(evt) => evt.stopPropagation()}
                      invalid={!!formik.errors.fromStartTime}
                      className="col-6"
                      title="YYYY-MM-DDTHH:MM"
                    />
                  </div>
                  <div className="d-flex align-items-center">
                    <Label className="col-3 mb-0" for="search__toStartTime">
                      to
                    </Label>
                    <Input
                      id="search__toStartTime"
                      type="datetime-local"
                      name="toStartTime"
                      autoComplete="off"
                      value={formik.values.toStartTime}
                      onBlur={formik.handleBlur}
                      onChange={formik.handleChange}
                      onKeyDown={(evt) => evt.stopPropagation()}
                      invalid={!!formik.errors.fromStartTime}
                      className="col-6"
                      title="YYYY-MM-DDTHH:MM"
                    />
                  </div>
                </div>
                {formik.errors.fromStartTime && (
                  <small className="text-danger">
                    {formik.errors.fromStartTime}
                  </small>
                )}
              </div>
            </Col>
            <Col
              xxl={4}
              sm={12}
              className="d-flex align-items-center flex-wrap mt-3"
            >
              <Label className="col-3 fw-bold mb-0">
                End time:
                <MdInfoOutline
                  id="search__endtime-infoicon"
                  fontSize="16"
                  className="ms-1"
                />
                <UncontrolledTooltip
                  trigger="hover"
                  delay={{ show: 0, hide: 200 }}
                  target="search__endtime-infoicon"
                  placement="right"
                  fade={false}
                  innerClassName="p-2 text-start text-nowrap md-fit-content"
                >
                  Format: YYYY-MM-DDTHH:MM (e.g., 2024-01-15T14:30)
                </UncontrolledTooltip>
              </Label>
              <div className="d-flex flex-column align-item-start">
                <div className="d-flex flex-column flex-wrap">
                  <div className="d-flex align-items-center mb-1">
                    <Label className="col-3 mb-0" for="search__fromEndTime">
                      from
                    </Label>
                    <Input
                      id="search__fromEndTime"
                      type="datetime-local"
                      name="fromEndTime"
                      autoComplete="off"
                      value={formik.values.fromEndTime}
                      onBlur={formik.handleBlur}
                      onChange={formik.handleChange}
                      onKeyDown={(evt) => evt.stopPropagation()}
                      invalid={!!formik.errors.fromEndTime}
                      className="col-6"
                      title="YYYY-MM-DDTHH:MM"
                    />
                  </div>
                  <div className="d-flex align-items-center">
                    <Label className="col-3 mb-0" for="search__toEndTime">
                      to
                    </Label>
                    <Input
                      id="search__toEndTime"
                      type="datetime-local"
                      name="toEndTime"
                      autoComplete="off"
                      value={formik.values.toEndTime}
                      onBlur={formik.handleBlur}
                      onChange={formik.handleChange}
                      onKeyDown={(evt) => evt.stopPropagation()}
                      invalid={!!formik.errors.fromEndTime}
                      className="col-6"
                      title="YYYY-MM-DDTHH:MM"
                    />
                  </div>
                </div>
                {formik.errors.fromEndTime && (
                  <small className="text-danger">{formik.errors.fromEndTime}</small>
                )}
              </div>
            </Col>
            <Col xxl={3} sm={12} className="d-flex align-items-center mt-3">
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
                  { value: "true", label: "Reports with errors" },
                  { value: "false", label: "Reports without errors" },
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
                invalid={!!(formik.touched.report && formik.errors.report)}
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
      {error && (
        <Row className="mt-3">
          <Col>
            <Alert color="danger" toggle={() => setError(null)}>
              {error}
            </Alert>
          </Col>
        </Row>
      )}
      <Row className="mt-4">
        <Loader
          loading={loadingData}
          render={() => (
            <DataTable
              // @ts-ignore - DataTable props are correct despite type definition mismatch
              data={elasticData}
              config={tableConfig}
              initialState={tableInitialState}
              columns={searchTableColumns}
              manualPagination
              pageCount={Math.ceil(totalCount / tableInitialState.pageSize)}
              onPageChange={handlePageChange}
              autoResetPage={false}
              {...tableProps}
            />
          )}
        />
      </Row>
    </Container>
  );
}
