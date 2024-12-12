/* eslint-disable react/prop-types */
import React from "react";
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
import { JSONTree } from "react-json-tree";
import { Loader, DataTable } from "@certego/certego-ui";

import { PluginsTypes, PluginFinalStatuses } from "../../constants/pluginConst";
import { searchTableColumns } from "./searchTableColumns";
import { pluginReportQueries } from "./searchApi";

// table config
const tableConfig = { enableExpanded: true, enableFlexLayout: true };
const tableInitialState = {
  pageSize: 10,
  sortBy: [{ id: "end_time", desc: false }],
};

const tableProps = {
  SubComponent: ({ row }) => (
    <div
      id={`jobreport-jsoninput-${row.id}`}
      style={{ maxHeight: "50vh", overflow: "scroll" }}
    >
      <JSONTree data={row.original?.report} keyPath={["report"]} />
    </div>
  ),
};

export default function Search() {
  const [elasticData, setElasticData] = React.useState([]);
  const [loadingData, setLoadingData] = React.useState(false);

  // default: 30days
  const defaultStartDate = new Date();
  defaultStartDate.setDate(defaultStartDate.getDate() - 30);

  const formik = useFormik({
    initialValues: {
      type: "",
      name: "",
      status: "",
      fromStartTime: defaultStartDate.toISOString().split("T")[0],
      toStartTime: new Date().toISOString().split("T")[0],
      fromEndTime: defaultStartDate.toISOString().split("T")[0],
      toEndTime: new Date().toISOString().split("T")[0],
      errors: "all",
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
        // start_start_time: new Date(formik.values.fromStartTime),
        // end_start_time: new Date(formik.values.toStartTime),
        // start_end_time: new Date(formik.values.fromEndTime),
        // end_end_time: new Date(formik.values.toEndTime),
      };
      Object.entries(formik.values).forEach(([key, value]) => {
        if (formik.initialValues[key] !== value)
          if (key === "type") queryParams.plugin_name = value;
          else if (
            key.includes([
              "start_start_time",
              "start_end_time",
              "end_start_time",
              "end_end_time",
            ])
          )
            queryParams[key] = new Date(value);
          else queryParams[key] = value;
      });
      console.debug(queryParams);

      let response = [];
      try {
        setLoadingData(true);
        response = await pluginReportQueries(queryParams);
      } catch (err) {
        // error will be handled by pluginReportQueries
      } finally {
        setLoadingData(false);
        setElasticData(response.data.data);
        formik.setSubmitting(false);
      }
    },
  });

  return (
    <Container fluid>
      <FormikProvider value={formik}>
        <Form onSubmit={formik.handleSubmit}>
          <Row className="mb-2">
            <Col className="d-flex align-items-end">
              <h1 id="reportSearch"> Search&nbsp;</h1>
              <span className="ms-4" style={{ marginBottom: "0.5rem" }}>
                Advanced search in plugin reports of the performed analysis.
                <MdInfoOutline
                  id="search__elastic-infoicon"
                  fontSize="20"
                  className="ms-2"
                />
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
                    to="https://intelowlproject.github.io/docs/IntelOwl/advanced_configuration/#elasticsearch"
                    target="_blank"
                  >
                    official doc.
                  </Link>
                </UncontrolledTooltip>
              </span>
            </Col>
          </Row>
          <Row id="search-input-fields-first-row" className="mt-4">
            <Col sm={4} className="d-flex align-items-center">
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
            <Col sm={4} className="d-flex align-items-center ms-4">
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
            <Col sm={3} className=" d-flex align-items-center ms-4">
              <Label className="col-4 fw-bold mb-0" for="search__status">
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
          <Row id="search-input-fields-second-row" className="mt-3">
            <Col sm={4} className="d-flex align-items-center">
              <Label className="col-3 fw-bold mb-0">Start time:</Label>
              <div className="d-flex flex-column align-item-start">
                <div className="d-flex flex-wrap">
                  <div className="d-flex align-items-center">
                    <Label className="me-2 mb-0" for="search__fromStartTime">
                      from:
                    </Label>
                    <Input
                      id="search__fromStartTime"
                      type="date"
                      name="fromStartTime"
                      autoComplete="off"
                      value={formik.values.fromStartTime}
                      onBlur={formik.handleBlur}
                      onChange={formik.handleChange}
                      invalid={formik.errors.startTime}
                    />
                  </div>
                  <div className="d-flex align-items-center ms-2">
                    <Label className="me-2 mb-0" for="search__toStartTime">
                      to:
                    </Label>
                    <Input
                      id="search__toStartTime"
                      type="date"
                      name="toStartTime"
                      autoComplete="off"
                      value={formik.values.toStartTime}
                      onBlur={formik.handleBlur}
                      onChange={formik.handleChange}
                      invalid={formik.errors.startTime}
                    />
                  </div>
                </div>
                {formik.errors.startTime && (
                  <small className="text-danger">
                    {formik.errors.startTime}
                  </small>
                )}
              </div>
            </Col>
            <Col sm={4} className="d-flex align-items-center ms-4">
              <Label className="col-3 fw-bold mb-0">End time:</Label>
              <div className="d-flex flex-column align-item-start">
                <div className="d-flex flex-wrap">
                  <div className="d-flex align-items-center">
                    <Label className="me-2 mb-0" for="search__fromEndTime">
                      from:
                    </Label>
                    <Input
                      id="search__fromEndTime"
                      type="date"
                      name="fromEndTime"
                      autoComplete="off"
                      value={formik.values.fromEndTime}
                      onBlur={formik.handleBlur}
                      onChange={formik.handleChange}
                      invalid={formik.errors.endTime}
                    />
                  </div>
                  <div className="d-flex align-items-center ms-2">
                    <Label className="me-2 mb-0" for="search__toEndTime">
                      to:
                    </Label>
                    <Input
                      id="search__toEndTime"
                      type="date"
                      name="toEndTime"
                      autoComplete="off"
                      value={formik.values.toEndTime}
                      onBlur={formik.handleBlur}
                      onChange={formik.handleChange}
                      invalid={formik.errors.endTime}
                    />
                  </div>
                </div>
                {formik.errors.endTime && (
                  <small className="text-danger">{formik.errors.endTime}</small>
                )}
              </div>
            </Col>
            <Col sm={3} className="d-flex align-items-center ms-4">
              <Label className="col-4 fw-bold mb-0" for="search__errors">
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
                {[
                  { value: "all", label: "All reports" },
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
          <Row id="search-input-fields-third-row" className="mt-3">
            <Col sm={11} className="d-flex align-items-center">
              <Label className="col-1 fw-bold mb-0" for="search__report">
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
                onChange={formik.handleChange}
                onBlur={formik.handleBlur}
                className="bg-darker border-dark ms-2"
                invalid={formik.touched.report && formik.errors.report}
              />
            </Col>
            <Col
              sm={1}
              className="d-flex align-items-center justify-content-end"
            >
              <Button
                id="search-button"
                className="d-flex align-items-center"
                size="sm"
                color="primary"
                type="submit"
                disabled={
                  !formik.isValid || formik.isSubmitting || !formik.dirty
                }
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
              {...tableProps}
            />
          )}
        />
      </Row>
    </Container>
  );
}
