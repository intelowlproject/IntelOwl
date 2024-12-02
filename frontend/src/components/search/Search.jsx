/* eslint-disable react/prop-types */
import React from "react";
import { useFormik, Form, FormikProvider, ErrorMessage } from "formik";
// import useAxios from "axios-hooks";
import {
  Container,
  Row,
  Col,
  Input,
  Label,
  FormGroup,
  UncontrolledTooltip,
  Button,
} from "reactstrap";
import { MdInfoOutline } from "react-icons/md";
import { JSONTree } from "react-json-tree";
import { Loader, DataTable } from "@certego/certego-ui";

import { PluginsTypes, PluginFinalStatuses } from "../../constants/pluginConst";
import { searchTableColumns } from "./searchTableColumns";

// table config
const tableConfig = { enableExpanded: true, enableFlexLayout: true };
const tableInitialState = {
  pageSize: 6,
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
  // data mock
  const loading = false;
  const error = null;
  const data = [
    {
      job: { id: 1 },
      config: {
        name: "Quad9_DNS",
        plugin_name: "analyzer",
      },
      status: "SUCCESS",
      start_time: "2024-11-27T09:56:59.555203Z",
      end_time: "2024-11-27T09:57:03.805453Z",
      errors: [],
      report: {
        observable: "google.com",
        resolutions: [
          {
            TTL: 268,
            data: "216.58.205.46",
            name: "google.com.",
            type: 1,
            Expires: "Wed, 27 Nov 2024 10:01:31 UTC",
          },
        ],
      },
    },
    {
      job: { id: 2 },
      config: {
        name: "Classic_DNS",
        plugin_name: "analyzer",
      },
      status: "SUCCESS",
      start_time: "2024-11-26T09:56:59.555203Z",
      end_time: "2024-11-26T09:57:03.805453Z",
      errors: [],
      report: {
        observable: "google.com",
        resolutions: [
          {
            TTL: 268,
            data: "216.58.205.46",
            name: "google.com.",
            type: 1,
            Expires: "Wed, 26 Nov 2024 10:01:31 UTC",
          },
        ],
      },
    },
  ];

  // API
  // const [{ data, loading, error }, refetch] = useAxios({
  //     url: ``,
  // });

  const formik = useFormik({
    initialValues: {
      type: "",
      name: "",
      status: "",
      startTimeGte: new Date().toISOString().split("T")[0],
      startTimeLte: new Date().toISOString().split("T")[0],
      endTimeGte: new Date().toISOString().split("T")[0],
      endTimeLte: new Date().toISOString().split("T")[0],
      reportErrors: false,
    },
    validate: (values) => {
      console.debug("validate - values");
      console.debug(values);
      const errors = {};

      if (Date.parse(values.startTimeLte) < Date.parse(values.startTimeGte)) {
        errors.startTimeLte = "Invalid date";
      }

      console.debug("formik validation errors");
      console.debug(errors);
      return errors;
    },
    onSubmit: async () => {
      console.debug("SUBMIT");
    },
  });
  console.debug(formik);

  return (
    <Container fluid>
      <FormikProvider value={formik}>
        <Form onSubmit={formik.handleSubmit}>
          <Row className="mb-2">
            <Col className="d-flex align-items-end">
              <h1 id="reportSearch"> Search&nbsp;</h1>
              <span className="ms-4" style={{ marginBottom: "0.5rem" }}>
                Advanced search in plugin reports of the performed analysis.
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
              <div className="d-flex align-items-center">
                <Label className="me-2 mb-0" for="search__startTimeGte">
                  from:
                </Label>
                <Input
                  id="search__startTimeGte"
                  type="date"
                  name="startTimeGte"
                  autoComplete="off"
                  value={formik.values.startTimeGte}
                  onBlur={formik.handleBlur}
                  onChange={formik.handleChange}
                  invalid={
                    formik.touched.startTimeGte && formik.errors.startTimeGte
                  }
                />
              </div>
              <div className="d-flex align-items-center ms-2">
                <Label className="me-2 mb-0" for="search__startTimeLte">
                  to:
                </Label>
                <div className="d-flex flex-column align-item-start">
                  <Input
                    id="search__startTimeLte"
                    type="date"
                    name="startTimeLte"
                    autoComplete="off"
                    value={formik.values.startTimeLte}
                    onBlur={formik.handleBlur}
                    onChange={formik.handleChange}
                    invalid={
                      formik.touched.startTimeLte && formik.errors.startTimeLte
                    }
                  />
                  <ErrorMessage
                    name="startTimeLte"
                    render={(msg) => (
                      <small className="text-danger">{msg}</small>
                    )}
                  />
                </div>
              </div>
            </Col>
            <Col sm={4} className="d-flex align-items-center ms-4">
              <Label className="col-3 fw-bold mb-0">End time:</Label>
              <div className="d-flex align-items-center">
                <Label className="me-2 mb-0" for="search__endTimeGte">
                  from:
                </Label>
                <Input
                  id="search__endTimeGte"
                  type="date"
                  name="endTimeGte"
                  autoComplete="off"
                  value={formik.values.endTimeGte}
                  onBlur={formik.handleBlur}
                  onChange={formik.handleChange}
                />
              </div>
              <div className="d-flex align-items-center ms-2">
                <Label className="me-2 mb-0" for="search__endTimeLte">
                  to:
                </Label>
                <Input
                  id="search__endTimeLte"
                  type="date"
                  name="endTimeLte"
                  autoComplete="off"
                  value={formik.values.endTimeLte}
                  onBlur={formik.handleBlur}
                  onChange={formik.handleChange}
                />
              </div>
            </Col>
            <Col sm={2} className="d-flex align-items-center ms-4">
              <FormGroup switch className="mb-0">
                <Label
                  check
                  className="fw-bold ms-2"
                  for="search__reportErrors"
                >
                  Errors in the report
                </Label>
                <Input
                  id="search__reportErrors"
                  type="switch"
                  name="reportErrors"
                  checked={formik.values.reportErrors}
                  value={formik.values.reportErrors}
                  onBlur={formik.handleBlur}
                  onChange={formik.handleChange}
                />
              </FormGroup>
            </Col>
          </Row>
          <Row id="search-input-fields-third-row" className="mt-3">
            <Col sm={11} className="d-flex align-items-center">
              <Label className="col-1 fw-bold mb-0" for="search__text-search">
                Text search:
                <MdInfoOutline
                  id="search__text-search-infoicon"
                  fontSize="20"
                  className="ms-2"
                />
                <UncontrolledTooltip
                  trigger="hover"
                  delay={{ show: 0, hide: 500 }}
                  target="search__text-search-infoicon"
                  placement="right"
                  fade={false}
                  innerClassName="p-2 text-start text-nowrap md-fit-content"
                >
                  Elastic docs:
                </UncontrolledTooltip>
              </Label>
              <Input
                id="search__text-search"
                type="text"
                name="test-search"
                value=""
                onChange={() => null}
                className="bg-darker border-dark ms-2"
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
                // onClick={onClick}
              >
                Search
              </Button>
            </Col>
          </Row>
        </Form>
      </FormikProvider>
      <Row className="mt-4">
        <Loader
          loading={loading}
          error={error}
          render={() => (
            <DataTable
              data={data}
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
