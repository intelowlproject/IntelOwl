/* eslint-disable react/prop-types */
import React from "react";
import { useFormik, Form, FormikProvider, FieldArray } from "formik";
import axios from "axios";
import {
  Container,
  Row,
  Col,
  Input,
  UncontrolledTooltip,
  Button,
  FormGroup,
} from "reactstrap";
import { MdInfoOutline } from "react-icons/md";
import { RiFileAddLine } from "react-icons/ri";
import { BsFillTrashFill, BsFillPlusCircleFill } from "react-icons/bs";
import { Loader, DataTable, addToast } from "@certego/certego-ui";

import { analyzablesTableColumns } from "./analyzablesTableColumns";
import { ANALYZABLES_URI } from "../../constants/apiURLs";
import { prettifyErrors } from "../../utils/api";
import { MultipleInputModal } from "../common/form/MultipleInputModal";

// table config
const tableConfig = {
  // enableSelection: true
};
const tableInitialState = {
  pageSize: 10,
  sortBy: [{ id: "discovery_date", desc: true }],
};

export default function Analyzables() {
  const [data, setData] = React.useState([]);
  const [loadingData, setLoadingData] = React.useState(false);

  const [isMultipleAnalyzablesModalOpen, setMultipleAnalyzablesModalOpen] =
    React.useState(false);
  const toggleMultipleAnalyzablesModal = React.useCallback(
    () => setMultipleAnalyzablesModalOpen((open) => !open),
    [setMultipleAnalyzablesModalOpen],
  );

  const formik = useFormik({
    initialValues: {
      analyzables: [""],
    },
    validate: (values) => {
      console.debug("validate - values");
      console.debug(values);
      const errors = {};
      return errors;
    },
    onSubmit: async () => {
      let response = null;
      const searchParams = new URLSearchParams();
      formik.values.analyzables
        .filter((value) => value !== "")
        .forEach((name) => searchParams.append("name", name));
      try {
        setLoadingData(true);
        response = await axios.get(
          `${ANALYZABLES_URI}?${searchParams.toString()}`,
        );
      } catch (error) {
        addToast("Search failed!", prettifyErrors(error), "danger", true);
      } finally {
        setLoadingData(false);
        setData(response.data.results);
        formik.setSubmitting(false);
      }
    },
  });

  return (
    <Container fluid>
      <FormikProvider value={formik}>
        <Form onSubmit={formik.handleSubmit}>
          <Row className="mb-2">
            <Col className="d-flex align-items-center">
              <h1 id="reportSearch">Analyzables&nbsp;</h1>
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
                  Analyzables are unique objects that can be analyzed multiple
                  times to have a different evaluation over time.
                </UncontrolledTooltip>
              </div>
            </Col>
          </Row>
          <Row id="search-input-fields-first-row d-flex flex-wrap">
            <FieldArray
              name="analyzables"
              render={(arrayHelpers) => (
                <FormGroup row>
                  <Col sm={9}>
                    <div style={{ maxHeight: "35vh", overflowY: "scroll" }}>
                      {formik.values.analyzables &&
                      formik.values.analyzables.length > 0
                        ? formik.values.analyzables.map((value, index) => (
                            <div
                              className="py-2 d-flex"
                              key={`analyzables-${index + 0}`}
                            >
                              <Col sm={10} className="pe-3">
                                <Input
                                  type="text"
                                  id={`analyzable-${index}`}
                                  name={`analyzable-${index}`}
                                  placeholder="google.com, 8.8.8.8, https://google.com, 1d5920f4b44b27a802bd77c4f0536f5a"
                                  className="input-dark"
                                  value={value}
                                  onChange={(event) => {
                                    const attributevalues =
                                      formik.values.analyzables;
                                    attributevalues[index] = event.target.value;
                                    formik.setFieldValue(
                                      "analyzables",
                                      attributevalues,
                                      false,
                                    );
                                  }}
                                />
                              </Col>
                              <Col sm={1} className="d-flex">
                                <Button
                                  color="primary"
                                  size="sm"
                                  id={`analyzable-${index}-deletebtn`}
                                  className="mx-auto rounded-1 d-flex align-items-center px-3"
                                  onClick={() => arrayHelpers.remove(index)}
                                  disabled={
                                    formik.values.analyzables.length === 1
                                  }
                                >
                                  <BsFillTrashFill />
                                </Button>
                                <Button
                                  color="primary"
                                  size="sm"
                                  id={`analyzable-${index}-addbtn`}
                                  className="mx-auto rounded-1 d-flex align-items-center px-3"
                                  onClick={() => arrayHelpers.push("")}
                                >
                                  <BsFillPlusCircleFill />
                                </Button>
                              </Col>
                            </div>
                          ))
                        : null}
                    </div>
                  </Col>
                  <Col
                    sm={2}
                    className="d-flex py-2 offset-1 justify-content-end align-items-start"
                  >
                    <Button
                      size="sm"
                      className="px-3 py-2 bg-tertiary border-tertiary d-flex align-items-center"
                      onClick={toggleMultipleAnalyzablesModal}
                    >
                      <RiFileAddLine className="me-1" /> Load multiple
                      analyzables
                    </Button>
                    {isMultipleAnalyzablesModalOpen && (
                      <MultipleInputModal
                        isOpen={isMultipleAnalyzablesModalOpen}
                        toggle={toggleMultipleAnalyzablesModal}
                        formik={formik}
                        formikSetField="analyzables"
                      />
                    )}
                  </Col>
                </FormGroup>
              )}
            />
          </Row>
          <Row>
            <Button
              size="m"
              type="submit"
              color="info"
              outline
              className="mx-auto rounded-0 col-sm-1 order-sm-5"
              disabled={
                formik.values.analyzables.length === 1 &&
                formik.values.analyzables[0] === ""
              }
            >
              Search
            </Button>
          </Row>
        </Form>
      </FormikProvider>
      <Row className="me-2" style={{ marginTop: "6%" }}>
        <div className="d-flex justify-content-between">
          <h4 className="py-0 mb-0">Results:</h4>
          {/* <Button
                size="sm"
                className="px-3 bg-tertiary border-0"
                disabled
            >
                Add your report
            </Button> */}
        </div>
      </Row>
      <Row className="mt-2 me-2">
        <Loader
          loading={loadingData}
          render={() => (
            <DataTable
              data={data}
              config={tableConfig}
              initialState={tableInitialState}
              columns={analyzablesTableColumns}
              autoResetPage
              // onSelectedRowChange={setSelectedRows}
              // isRowSelectable={(row) => !row.original.completed}
            />
          )}
        />
      </Row>
    </Container>
  );
}
