/* eslint-disable react/prop-types */
import React from "react";
import useTitle from "react-use/lib/useTitle";
import { useFormik, Form, FormikProvider } from "formik";
import axios from "axios";
import { Container, Row, Col, UncontrolledTooltip, Button } from "reactstrap";
import { MdInfoOutline } from "react-icons/md";
import { RiFileAddLine } from "react-icons/ri";
import { BsFillPlusCircleFill } from "react-icons/bs";
import { Loader, DataTable, addToast } from "@certego/certego-ui";

import { analyzablesTableColumns } from "./analyzablesTableColumns";
import { ANALYZABLES_URI } from "../../constants/apiURLs";
import { prettifyErrors } from "../../utils/api";
import { MultipleInputModal } from "../common/form/MultipleInputModal";
import { ListInput } from "../common/form/ListInput";
import { UserEventModal } from "../userEvents/UserEventModal";

// table config
const tableConfig = {
  enableSelection: true,
};
const tableInitialState = {
  pageSize: 10,
  sortBy: [{ id: "discovery_date", desc: true }],
};

export default function Analyzables() {
  // page title
  useTitle(`IntelOwl | Artifacts`, { restoreOnUnmount: true });

  const [data, setData] = React.useState([]);
  const [loadingData, setLoadingData] = React.useState(false);

  const [isMultipleAnalyzablesModalOpen, setMultipleAnalyzablesModalOpen] =
    React.useState(false);
  const toggleMultipleAnalyzablesModal = React.useCallback(
    () => setMultipleAnalyzablesModalOpen((open) => !open),
    [setMultipleAnalyzablesModalOpen],
  );

  const [showUserEventModal, setShowUserEventModal] = React.useState(false);
  const [selectedRows, setSelectedRows] = React.useState([]);

  const doSearch = React.useCallback(
    async (analyzableNames) => {
      let response = null;
      const searchParams = new URLSearchParams();
      analyzableNames
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
        const resultData = [];
        if (response.data.count !== analyzableNames.length) {
          analyzableNames.forEach((analyzableName) => {
            if (
              response.data.results
                .map((result) => result.name)
                .includes(analyzableName)
            ) {
              resultData.push(
                response.data.results.filter(
                  (result) => result.name === analyzableName,
                )[0],
              );
            } else {
              resultData.push({
                name: analyzableName,
                last_data_model: { tags: ["not_found"] },
              });
            }
          });
          setData(resultData);
        } else {
          setData(response.data.results);
        }
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  );

  const formik = useFormik({
    initialValues: {
      analyzables: [""],
    },
    onSubmit: async () => {
      await doSearch(formik.values.analyzables);
      formik.setSubmitting(false);
    },
  });

  const onEvaluationSuccess = React.useCallback(
    (submittedAnalyzables) => {
      const firstAnalyzable = submittedAnalyzables[0];
      if (firstAnalyzable) {
        formik.setFieldValue("analyzables", [firstAnalyzable], false);
        doSearch([firstAnalyzable]);
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [doSearch],
  );

  return (
    <Container fluid>
      <FormikProvider value={formik}>
        <Form onSubmit={formik.handleSubmit}>
          <Row className="mb-2">
            <Col className="d-flex align-items-center">
              <h1 id="reportSearch">Artifacts&nbsp;</h1>
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
                  Artifacts are unique objects that can be analyzed multiple
                  times to have a different evaluation over time.
                </UncontrolledTooltip>
              </div>
            </Col>
          </Row>
          <Row
            id="search-input-fields-first-row"
            className="d-flex flex-wrap me-2"
          >
            <Col sm={9}>
              <ListInput
                id="analyzables"
                values={formik.values.analyzables}
                formikSetFieldValue={formik.setFieldValue}
                placeholder="google.com, 8.8.8.8, https://google.com, 1d5920f4b44b27a802bd77c4f0536f5a"
                formikHandlerBlur={formik.handleBlur}
              />
            </Col>
            <Col
              sm={3}
              className="d-flex py-2 justify-content-end align-items-start"
            >
              <Button
                size="sm"
                className="px-3 me-2 bg-tertiary border-tertiary d-flex align-items-center"
                onClick={toggleMultipleAnalyzablesModal}
              >
                <RiFileAddLine className="me-1" /> Multiple artifacts
              </Button>
              {isMultipleAnalyzablesModalOpen && (
                <MultipleInputModal
                  isOpen={isMultipleAnalyzablesModalOpen}
                  toggle={toggleMultipleAnalyzablesModal}
                  formik={formik}
                  formikSetField="analyzables"
                />
              )}
              <Button
                id="newUserEvaluationBtn"
                size="sm"
                className="px-3 bg-tertiary border-tertiary d-flex align-items-center"
                onClick={() => setShowUserEventModal(!showUserEventModal)}
              >
                <BsFillPlusCircleFill className="me-1" /> New evaluation
              </Button>
            </Col>
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
          <Button
            id="addUserEvaluationBtn"
            size="sm"
            className="px-3 bg-tertiary border-tertiary d-flex align-items-center"
            disabled={data?.length === 0 || selectedRows.length === 0}
            onClick={() => setShowUserEventModal(!showUserEventModal)}
          >
            <BsFillPlusCircleFill className="me-1" /> Your evaluation
          </Button>
        </div>
      </Row>
      {showUserEventModal && (
        <UserEventModal
          analyzables={
            selectedRows.length > 0 ? selectedRows.map((row) => row) : [""]
          }
          toggle={setShowUserEventModal}
          isOpen={showUserEventModal}
          onSuccess={onEvaluationSuccess}
        />
      )}
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
              onSelectedRowChange={setSelectedRows}
              isRowSelectable={(row) => !row.original.completed}
            />
          )}
        />
      </Row>
    </Container>
  );
}
