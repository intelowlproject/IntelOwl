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
  Spinner,
} from "reactstrap";

import { Loader } from "@certego/certego-ui";

import { useNavigate, useLocation } from "react-router-dom";
import { PluginsReportTable } from "./pluginReportTables";
import {
  reportedPluginNumber,
  reportedVisualizerNumber,
  ReportedPluginTooltip,
} from "./utils/reportedPlugins";
import { StatusIcon } from "../../common/icon/StatusIcon";
import VisualizerReport from "../../common/visualizer/visualizer";
import { JobFinalStatuses } from "../../../constants/jobConst";
import { PluginStatuses } from "../../../constants/pluginConst";
import { JobResultSections } from "../../../constants/miscConst";

import { JobInfoCard } from "./JobInfoCard";
import { JobIsRunningAlert } from "./JobIsRunningAlert";
import { JobActionsBar } from "./bar/JobActionBar";
import { usePluginConfigurationStore } from "../../../stores/usePluginConfigurationStore";
import { JsonEditor } from "../../common/JsonEditor";

/* THESE IDS CANNOT BE EMPTY!
We perform a redirect in case the user landed in the visualzier page without a visualizer,
this is case happens because we don't know the available visualizers before enter in the job page:
ex: when we start a job from start scan we cannot know the visualizer pages.
When we land in the job page without a visualizer selected we need to redirect the user to a valid visualizer,
the redirect is based on the url: in case the parmam miss it means the page is not selected and we need to redirect
in case we use empty param for this page we fall in an infinite redirect loop.
*/
const LOADING_VISUALIZER_UI_ELEMENT_CODE = "loading";
const NO_VISUALIZER_UI_ELEMENT_CODE = "no-visualizer";

export function JobOverview({
  isRunningJob,
  job,
  relatedInvestigationNumber,
  refetch,
  section,
  subSection,
}) {
  console.debug("JobOverview rendered");
  console.debug(`section: ${section}, subSection: ${subSection}`);

  const isSelectedUI = section === JobResultSections.VISUALIZER;

  const [
    analyzersLoading,
    connectorsLoading,
    visualizersLoading,
    pivotsLoading,
    analyzers,
    connectors,
    visualizers,
    pivots,
  ] = usePluginConfigurationStore((state) => [
    state.analyzersLoading,
    state.connectorsLoading,
    state.visualizersLoading,
    state.pivotsLoading,
    state.analyzers,
    state.connectors,
    state.visualizers,
    state.pivots,
  ]);

  const rawElements = React.useMemo(
    () => [
      {
        name: "analyzer",
        nav: (
          <div className="d-flex-center">
            <strong>Analyzers Report</strong>
            <Badge id="analyzersReportsBadge" className="ms-2">
              {reportedPluginNumber(job.analyzer_reports)} /&nbsp;
              {job.analyzers_to_execute.length}
            </Badge>
            <ReportedPluginTooltip
              id="analyzersReportsBadge"
              pluginName="analyzers"
            />
          </div>
        ),
        report: (
          <PluginsReportTable
            job={job}
            refetch={refetch}
            pluginReports={job?.analyzer_reports}
            pluginsStored={analyzers}
            pluginsStoredLoading={analyzersLoading}
          />
        ),
      },
      {
        name: "connector",
        nav: (
          <div className="d-flex-center">
            <strong>Connectors Report</strong>
            <Badge id="connectorsReportsBadge" className="ms-2">
              {reportedPluginNumber(job.connector_reports)} /&nbsp;
              {job.connectors_to_execute.length}
            </Badge>
            <ReportedPluginTooltip
              id="connectorsReportsBadge"
              pluginName="connectors"
            />
          </div>
        ),
        report: (
          <PluginsReportTable
            job={job}
            refetch={refetch}
            pluginReports={job?.connector_reports}
            pluginsStored={connectors}
            pluginsStoredLoading={connectorsLoading}
          />
        ),
      },
      {
        name: "pivot",
        nav: (
          <div className="d-flex-center">
            <strong>Pivots Report</strong>
            <Badge id="pivotsReportsBadge" className="ms-2">
              {reportedPluginNumber(job.pivot_reports)} /&nbsp;
              {job.pivots_to_execute.length}
            </Badge>
            <ReportedPluginTooltip
              id="pivotsReportsBadge"
              pluginName="pivots"
            />
          </div>
        ),
        report: (
          <PluginsReportTable
            job={job}
            refetch={refetch}
            pluginReports={job?.pivot_reports}
            pluginsStored={pivots}
            pluginsStoredLoading={pivotsLoading}
          />
        ),
      },
      {
        name: "visualizer",
        nav: (
          <div className="d-flex-center">
            <strong>Visualizers Report</strong>
            <Badge id="visualizersReportsBadge" className="ms-2">
              {reportedVisualizerNumber(
                job.visualizer_reports,
                job.visualizers_to_execute,
              )}{" "}
              /&nbsp;
              {job.visualizers_to_execute.length}
            </Badge>
            <ReportedPluginTooltip
              id="visualizersReportsBadge"
              pluginName="visualizers"
            />
          </div>
        ),
        report: (
          <PluginsReportTable
            job={job}
            refetch={refetch}
            pluginReports={job?.visualizer_reports}
            pluginsStored={visualizers}
            pluginsStoredLoading={visualizersLoading}
          />
        ),
      },
      {
        name: "full",
        nav: (
          <div className="d-flex-center">
            <strong>Full Report</strong>
          </div>
        ),
        report: (
          <div
            id={`jobfullreport-jsoninput-${job.id}`}
            style={{ height: "65vh", overflow: "scroll" }}
          >
            <JsonEditor
              id="job_full_report_json"
              initialJsonData={job}
              height="65vh"
              width="100%"
              readOnly
            />
          </div>
        ),
      },
      {
        name: "data_model",
        nav: (
          <div className="d-flex-center">
            <strong>Data Model</strong>
          </div>
        ),
        report: (
          <div
            id={`jobdatamodel-jsoninput-${job.id}`}
            style={{ height: "65vh", overflow: "scroll" }}
          >
            <JsonEditor
              id="job_data_model_json"
              initialJsonData={job.data_model}
              height="65vh"
              width="100%"
              readOnly
            />
          </div>
        ),
      },
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [
      job,
      analyzersLoading,
      connectorsLoading,
      visualizersLoading,
      pivotsLoading,
    ],
  );

  // state
  const navigate = useNavigate();
  const location = useLocation();
  const [UIElements, setUIElements] = useState([]);
  console.debug(
    `location pathname: ${
      location.pathname
    }, state - userChanged: ${JSON.stringify(
      location?.state?.userChanged,
    )}, state - jobReport: #${location?.state?.jobReport.id}`,
  );

  useEffect(() => {
    console.debug("JobOverview - check to set default visualizer");
    let visualizerSections = [];
    if (Object.values(JobFinalStatuses).includes(job.status)) {
      const pageList = job.visualizer_reports.map((report) => report.name);
      if (pageList.length > 0) {
        visualizerSections = pageList;
      } else {
        visualizerSections = [NO_VISUALIZER_UI_ELEMENT_CODE];
      }
    } else {
      visualizerSections = [LOADING_VISUALIZER_UI_ELEMENT_CODE];
    }
    console.debug(`visualizerSections: ${JSON.stringify(visualizerSections)}`);

    // check visualizers have been loaded and user didn't changed page
    if (visualizerSections !== 0 && !location.state?.userChanged) {
      console.debug("updated visualizers");
      if (!subSection) {
        console.debug(
          `[AUTO REDIRECT] navigate to visualizer: ${
            visualizerSections[0]
          }, encoded: ${encodeURIComponent(visualizerSections[0])}`,
        );
        // in case no section is selected (ex: from start scan) redirect to a visualizer
        navigate(
          `/jobs/${job.id}/${JobResultSections.VISUALIZER}/${encodeURIComponent(
            visualizerSections[0],
          )}`,
          { replace: true },
        );
      } else if (
        subSection === LOADING_VISUALIZER_UI_ELEMENT_CODE &&
        visualizerSections[0] !== LOADING_VISUALIZER_UI_ELEMENT_CODE
      ) {
        console.debug(
          `[AUTO REDIRECT] navigate to visualizer: ${
            visualizerSections[0].id
          }, encoded: ${encodeURIComponent(visualizerSections[0])}`,
        );
        // in case we are in the loading page and we update the visualizer change page (if they are different from loading)
        navigate(
          `/jobs/${job.id}/${JobResultSections.VISUALIZER}/${encodeURIComponent(
            visualizerSections[0],
          )}`,
          { replace: true },
        );
      } else if (subSection === NO_VISUALIZER_UI_ELEMENT_CODE) {
        console.debug("[AUTO REDIRECT] navigate to raw data - analyzer");
        // in case there is no visualizer redirect to raw data
        navigate(
          `/jobs/${job.id}/${JobResultSections.RAW}/${rawElements[0].name}`,
          { replace: true },
        );
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [job]);

  useEffect(() => {
    // this store the ui elements when the frontend download them
    console.debug("JobOverview - create/update visualizer components");
    console.debug(job);
    let newUIElements = [];

    // 1) generate UI elements in case all visualizers are completed
    if (
      Object.values(JobFinalStatuses).includes(job.status) &&
      job.visualizers_to_execute.length > 0
    ) {
      newUIElements = job.visualizer_reports.map((visualizerReport) => ({
        name: visualizerReport.name,
        nav: (
          <div className="d-flex-center">
            <strong>{visualizerReport.name}</strong>
            {visualizerReport.status !== PluginStatuses.SUCCESS && (
              <StatusIcon className="ms-2" status={visualizerReport.status} />
            )}
          </div>
        ),
        report: <VisualizerReport visualizerReport={visualizerReport} />,
      }));
    }

    // 2) in case visualizers are running put a loader
    if (
      !Object.values(JobFinalStatuses).includes(job.status) &&
      job.visualizers_to_execute.length > 0
    ) {
      newUIElements.push({
        name: LOADING_VISUALIZER_UI_ELEMENT_CODE,
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
    if (job.visualizers_to_execute.length === 0) {
      newUIElements.push({
        name: NO_VISUALIZER_UI_ELEMENT_CODE,
        nav: null,
        report: (
          <p className="text-center">
            No visualizers available. You can consult the results in the raw
            format.{" "}
          </p>
        ),
      });
    }

    setUIElements(newUIElements);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [job]);

  const elementsToShow = isSelectedUI ? UIElements : rawElements;

  return (
    <Loader
      loading={UIElements.length === 0}
      render={() => (
        <Container fluid>
          {/* bar with job id and utilities buttons */}
          <Row
            className="g-0 d-flex-between-end align-items-center mb-2"
            id="utilitiesRow"
          >
            <Col md={4}>
              <h2 className="d-flex align-items-center mb-0">
                <span className="me-2 text-secondary">Job #{job.id}</span>
                <StatusIcon status={job.status} className="small" />
              </h2>
            </Col>
            <Col
              md={8}
              className="d-flex justify-content-end align-items-center"
            >
              <JobActionsBar
                job={job}
                relatedInvestigationNumber={relatedInvestigationNumber}
              />
            </Col>
          </Row>
          {/* job metadata card */}
          <Row className="g-0">
            <Col>
              <JobInfoCard job={job} />
            </Col>
          </Row>
          {isRunningJob && (
            <Row
              className="my-4 d-flex justify-content-center"
              style={{ width: "100%" }}
            >
              <JobIsRunningAlert job={job} />
            </Row>
          )}
          <Row className="g-0 mt-3">
            <div className="mb-2 d-inline-flex flex-row-reverse">
              {/* UI/raw switch */}
              <ButtonGroup className="ms-2">
                <Button
                  outline={!isSelectedUI}
                  color={isSelectedUI ? "secondary" : "tertiary"}
                  onClick={() =>
                    navigate(
                      `/jobs/${job.id}/${
                        JobResultSections.VISUALIZER
                      }/${encodeURIComponent(UIElements[0].name)}`,
                      { state: { userChanged: true, jobReport: job } },
                    )
                  }
                >
                  {JobResultSections.VISUALIZER.charAt(0).toUpperCase() +
                    JobResultSections.VISUALIZER.slice(1)}
                </Button>
                <Button
                  outline={isSelectedUI}
                  color={!isSelectedUI ? "secondary" : "tertiary"}
                  onClick={() =>
                    navigate(
                      `/jobs/${job.id}/${JobResultSections.RAW}/${rawElements[0].name}`,
                      { state: { userChanged: true, jobReport: job } },
                    )
                  }
                >
                  {JobResultSections.RAW.charAt(0).toUpperCase() +
                    JobResultSections.RAW.slice(1)}
                </Button>
              </ButtonGroup>
              <div className="flex-fill horizontal-scrollable">
                <Nav tabs className="flex-nowrap h-100">
                  {/* generate the nav with the UI/raw visualizers avoid to generate the navbar item for the "no visualizer element" */}
                  {elementsToShow.map(
                    (componentsObject) =>
                      componentsObject.id !== "" &&
                      componentsObject.name !==
                        LOADING_VISUALIZER_UI_ELEMENT_CODE && (
                        <NavItem>
                          <NavLink
                            className={`${
                              // ignore the loading id or the "active" class create an empty block in the navbar
                              subSection === componentsObject.name &&
                              componentsObject.name !== ""
                                ? "active"
                                : ""
                            }`}
                            onClick={() =>
                              navigate(
                                `/jobs/${
                                  job.id
                                }/${section}/${encodeURIComponent(
                                  componentsObject.name,
                                )}`,
                                {
                                  state: { userChanged: true, jobReport: job },
                                },
                              )
                            }
                          >
                            {componentsObject.nav}
                          </NavLink>
                        </NavItem>
                      ),
                  )}
                </Nav>
              </div>
            </div>
            {/* reports section */}
            <TabContent activeTab={subSection}>
              {elementsToShow.sort().map((componentsObject) => (
                <TabPane
                  tabId={componentsObject.name}
                  id={`jobReportTab${componentsObject.name}`}
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
  relatedInvestigationNumber: PropTypes.number.isRequired,
  refetch: PropTypes.func.isRequired,
  section: PropTypes.string.isRequired,
  subSection: PropTypes.string.isRequired,
};
