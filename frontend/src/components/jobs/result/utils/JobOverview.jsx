import React, { useEffect, useState } from "react";
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

export default function JobOverview({ isRunningJob, job, refetch }) {
  console.debug("JobOverview rendered");

  // state
  const [UIElements, setUIElements] = useState({});
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
  const selectUISection = (isUI) => {
    setIsSelectedUI(isUI);
    setActiveElement(Object.keys(isUI ? UIElements : rawElements)[0]);
  };

  useEffect(() => {
    // this use effect is triggered when the component is mounted to reset the previously subSection selection
    resetJobOverview();
  }, [resetJobOverview]);

  // UI elements (note: this useEffect MUST be AFTER the reset useEffect)
  useEffect(() => {
    // TODO (remove the mock): load visualizers from the backend only once
    const newUIElements = {};
    // eslint-disable-next-line no-plusplus
    for (let i = 0; i < 1; i++) {
      const elementLabel = `Visualizer Report ${i}`;
      newUIElements[elementLabel] = {
        nav: (
          <div className="d-flex-center">
            <strong>{elementLabel}</strong>
          </div>
        ),
        report: <VisualizerReport job={job} />,
      };
    }
    setUIElements(newUIElements);
    /* set the default to the first visualizer only in case the UI is selected.
    In case raw data is selected don't change or during polling (long jobs) we reset the view and change the UI to the user.    
    */
    if (isSelectedUI) {
      setActiveElement(Object.keys(newUIElements)[0]);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [job]);
  // raw elements
  let AnalyzerDenominator = job.analyzers_requested?.length || "all";
  let ConnectorDenominator = job.connectors_requested?.length || "all";
  const VisualizerDenominator = "all";

  if (job.playbook_to_execute) {
    AnalyzerDenominator = job.analyzers_to_execute.length;
    if (job.connectors_to_execute?.length === 0) {
      ConnectorDenominator = "0";
    } else {
      ConnectorDenominator = job.connectors_to_execute.length;
    }
  }
  const rawElements = React.useMemo(
    () => ({
      "Analyzers Report": {
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
      "Connectors Report": {
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
      "Visualizers Report": {
        nav: (
          <div className="d-flex-center">
            <strong>Visualizers Report</strong>
            <Badge className="ms-2">
              {job.visualizers_to_execute?.length} /&nbsp;
              {VisualizerDenominator}
            </Badge>
          </div>
        ),
        report: <VisualizersReportTable job={job} refetch={refetch} />,
      },
    }),
    [job, refetch, AnalyzerDenominator, ConnectorDenominator]
  );

  console.debug(`JobOverview - isSelectedUI: ${isSelectedUI}`);
  console.debug(`JobOverview - activeElement: ${activeElement}`);

  const elementsToShow = isSelectedUI ? UIElements : rawElements;
  return (
    <Loader
      loading={UIElements === {}}
      render={() => (
        <Container fluid>
          {/* bar with job id and utilities buttons */}
          <Row className="g-0 d-flex-between-end">
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
                <Nav tabs className="flex-nowrap">
                  {/* generate the nav with the UI/raw visualizers */}
                  {Object.entries(elementsToShow).map(
                    ([navTitle, componentsObject]) => (
                      <NavItem>
                        <NavLink
                          className={`${
                            activeElement === navTitle ? "active" : ""
                          }`}
                          onClick={() => setActiveElement(navTitle)}
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
              {Object.entries(elementsToShow).map(
                ([navTitle, componentsObject]) => (
                  <TabPane tabId={navTitle}>{componentsObject.report}</TabPane>
                )
              )}
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
