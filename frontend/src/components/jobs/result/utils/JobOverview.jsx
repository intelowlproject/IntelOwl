import React, { useEffect, useState, useCallback } from "react";
import PropTypes from "prop-types";
import {
  ButtonGroup,
  Button,
  Badge,
  Col,
  Row,
  Nav,
  NavItem,
  NavLink,
  Container,
  TabContent,
  TabPane,
  Spinner,
} from "reactstrap";

import { GoBackButton, Loader } from "@certego/certego-ui";

import {
  AnalyzersReportTable,
  ConnectorsReportTable,
  VisualizersReportTable,
} from "./tables";
import { JobInfoCard, JobIsRunningAlert, JobActionsBar } from "./sections";
import { StatusIcon } from "../../../common";
import VisualizerReport from "../visualizer/visualizer";
import useJobOverviewStore from "../../../../stores/useJobOverviewStore";

const LOADING_VISUALIZER_UI_ELEMENT_CODE = -2;
const NO_VISUALIZER_UI_ELEMENT_CODE = -1;

export default function JobOverview({ isRunningJob, job, refetch }) {
  console.debug("JobOverview rendered");

  // raw elements
  let AnalyzerDenominator = job.analyzers_to_execute?.length || "all";
  let ConnectorDenominator = job.connectors_to_execute?.length || "all";

  if (job.playbook_to_execute) {
    AnalyzerDenominator = job.analyzers_to_execute.length;
    if (job.connectors_to_execute?.length === 0) {
      ConnectorDenominator = "0";
    } else {
      ConnectorDenominator = job.connectors_to_execute.length;
    }
  }
  const rawElements = React.useMemo(
    () => [
      {
        id: 1,
        nav: (
          <div className="d-flex-center">
            <strong>Analyzers Report</strong>
            <Badge className="ms-2">
              {job.analyzers_to_execute?.length} /&nbsp;
              {AnalyzerDenominator}
            </Badge>
          </div>
        ),
        report: <AnalyzersReportTable job={job} refetch={refetch} />,
      },
      {
        id: 2,
        nav: (
          <div className="d-flex-center">
            <strong>Connectors Report</strong>
            <Badge className="ms-2">
              {job.connectors_to_execute?.length} /&nbsp;
              {ConnectorDenominator}
            </Badge>
          </div>
        ),
        report: <ConnectorsReportTable job={job} refetch={refetch} />,
      },
      {
        id: 3,
        nav: (
          <div className="d-flex-center">
            <strong>Visualizers Report</strong>
            <Badge className="ms-2">
              {job.visualizers_to_execute?.length} /&nbsp; all
            </Badge>
          </div>
        ),
        report: <VisualizersReportTable job={job} refetch={refetch} />,
      },
    ],
    [job, refetch, AnalyzerDenominator, ConnectorDenominator]
  );

  // state
  const [UIElements, setUIElements] = useState([]);
  const [
    isSelectedUI,
    activeElement,
    setIsSelectedUI,
    setActiveElement,
    resetJobOverview,
  ] = useJobOverviewStore((state) => [
    state.isSelectedUI,
    state.activeElement,
    state.setIsSelectedUI,
    state.setActiveElement,
    state.resetJobOverview,
  ]);
  const selectUISection = useCallback(
    (isUI) => {
      setIsSelectedUI(isUI);
      setActiveElement((isUI ? UIElements : rawElements)[0].id);
    },
    [UIElements, rawElements, setActiveElement, setIsSelectedUI]
  );

  // NOTE: use effect order is important! Reset MUST BE defined before the other!
  useEffect(() => {
    console.debug("JobOverview - reset UI/raw data selection");
    // this use effect is triggered when the component is mounted to reset the previously subSection selection
    resetJobOverview();
  }, [resetJobOverview]);

  useEffect(() => {
    console.debug("JobOverview - create/update visualizer components");
    console.debug(job);

    // 1) generate UI elements in case visualizers terminated
    const newUIElements = job.visualizer_reports.map((visualizerReport) => ({
      id: visualizerReport.id,
      nav: (
        <div className="d-flex-center">
          <strong>{visualizerReport.name}</strong>
        </div>
      ),
      report: <VisualizerReport visualizerReport={visualizerReport} />,
    }));

    // 2) in case visualizers are running put a loader
    if (newUIElements.length === 0 && job.visualizers_to_execute.length > 0) {
      newUIElements.push({
        id: LOADING_VISUALIZER_UI_ELEMENT_CODE,
        nav: null,
        report: (
          <div
            className="d-flex justify-content-center"
            id="visualizerLoadingSpinner"
          >
            <Spinner />
          </div>
        ),
      });
    }

    // 3) in case there are no visualizers add a "no data" visualizer
    if (newUIElements.length === 0) {
      newUIElements.push({
        id: NO_VISUALIZER_UI_ELEMENT_CODE,
        nav: null,
        report: <p className="text-center">No visualizers available.</p>,
      });
    }

    setUIElements(newUIElements);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [job]);

  useEffect(() => {
    console.debug("JobOverview - check to set default visualizer");
    /* set the default to the first visualizer only in case no section is selected and UI elements have been downloaded.
    In case a section is selected and job data are refreshed (thanks to the polling) do NOT change the section the user is watching
    */
    if (
      UIElements.length !== 0 &&
      [undefined, LOADING_VISUALIZER_UI_ELEMENT_CODE].includes(activeElement)
    ) {
      const firstVisualizer = UIElements[0];
      if (firstVisualizer.id === NO_VISUALIZER_UI_ELEMENT_CODE) {
        selectUISection(false);
      } else {
        console.debug(
          `set default visualizer to: ${firstVisualizer.name} (id: ${firstVisualizer.id})`
        );
        setActiveElement(firstVisualizer.id);
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [UIElements]);

  console.debug(`JobOverview - isSelectedUI: ${isSelectedUI}`);
  console.debug(`JobOverview - activeElement: ${activeElement}`);

  const elementsToShow = isSelectedUI ? UIElements : rawElements;
  return (
    <Loader
      loading={UIElements.length === 0}
      render={() => (
        <Container fluid>
          {/* bar with job id and utilities buttons */}
          <Row className="g-0 d-flex-between-end" id="utilitiesRow">
            <Col>
              <GoBackButton onlyIcon color="gray" />
              <h2>
                <span className="me-2 text-secondary">Job #{job.id}</span>
                <StatusIcon status={job.status} className="small" />
              </h2>
            </Col>
            <Col className="d-flex justify-content-end">
              <JobActionsBar job={job} />
            </Col>
          </Row>
          {/* job metadata card */}
          <Row className="g-0">
            <Col>
              <JobInfoCard job={job} />
            </Col>
          </Row>
          {isRunningJob && (
            <Row>
              <JobIsRunningAlert job={job} />
            </Row>
          )}
          <Row className="g-0 mt-3">
            <div className="mb-2 d-inline-flex flex-row-reverse">
              {/* UI/raw switch */}
              <ButtonGroup className="ms-2 mb-3">
                <Button
                  outline={!isSelectedUI}
                  color={isSelectedUI ? "primary" : "tertiary"}
                  onClick={() => selectUISection(true)}
                >
                  Visualizer
                </Button>
                <Button
                  outline={isSelectedUI}
                  color={!isSelectedUI ? "primary" : "tertiary"}
                  onClick={() => selectUISection(false)}
                >
                  Raw
                </Button>
              </ButtonGroup>
              <div className="flex-fill horizontal-scrollable">
                <Nav tabs className="flex-nowrap h-100">
                  {/* generate the nav with the UI/raw visualizers avoid to generate the navbar item for the "no visualizer element" */}
                  {elementsToShow.map(
                    (componentsObject) =>
                      componentsObject.id !== NO_VISUALIZER_UI_ELEMENT_CODE && (
                        <NavItem>
                          <NavLink
                            className={`${
                              // ignore the loading id or the "active" class create an empty block in the navbar
                              activeElement === componentsObject.id &&
                              componentsObject.id !==
                                LOADING_VISUALIZER_UI_ELEMENT_CODE
                                ? "active"
                                : ""
                            }`}
                            onClick={() =>
                              setActiveElement(componentsObject.id)
                            }
                          >
                            {componentsObject.nav}
                          </NavLink>
                        </NavItem>
                      )
                  )}
                </Nav>
              </div>
            </div>
            {/* reports section */}
            <TabContent activeTab={activeElement}>
              {elementsToShow.map((componentsObject) => (
                <TabPane
                  tabId={componentsObject.id}
                  id={`jobReportTab${componentsObject.id}`}
                >
                  {componentsObject.report}
                </TabPane>
              ))}
            </TabContent>
          </Row>
        </Container>
      )}
    />
  );
}

JobOverview.propTypes = {
  isRunningJob: PropTypes.bool.isRequired,
  job: PropTypes.object.isRequired,
  refetch: PropTypes.func.isRequired,
};
