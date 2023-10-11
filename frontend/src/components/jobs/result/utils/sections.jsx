/* eslint-disable no-param-reassign */
/* eslint-disable react/prop-types */
/* eslint-disable camelcase */
import React from "react";
import PropTypes from "prop-types";
import {
  Button,
  ListGroup,
  ListGroupItem,
  Badge,
  Fade,
  Collapse,
  Row,
  Col,
  UncontrolledTooltip,
} from "reactstrap";
import { useNavigate } from "react-router-dom";
import { VscGlobe, VscFile, VscJson } from "react-icons/vsc";
import { FaFileDownload } from "react-icons/fa";
import {
  MdDeleteOutline,
  MdPauseCircleOutline,
  MdOutlineRefresh,
  MdComment,
} from "react-icons/md";

import {
  ContentSection,
  DateHoverable,
  SocialShareBtn,
  IconAlert,
  IconButton,
  addToast,
  CopyToClipboardButton,
  ArrowToggleIcon,
} from "@certego/certego-ui";

import { SaveAsPlaybookButton } from "./SaveAsPlaybooksForm";

import { JobTag, PlaybookTag, StatusTag, TLPTag } from "../../../common";
import { downloadJobSample, deleteJob, killJob } from "../api";
import { createJob, createPlaybookJob } from "../../../scan/api";
import {
  pluginFinalStatuses,
  jobStatuses,
  scanMode,
  jobResultSection,
} from "../../../../constants/constants";

function DeleteIcon() {
  return (
    <span>
      <MdDeleteOutline className="text-danger" /> Delete Job
    </span>
  );
}

function CommentIcon({ commentNumber }) {
  return (
    <span>
      <MdComment className="me-1" />
      Comments ({commentNumber})
    </span>
  );
}

function retryJobIcon() {
  return (
    <span>
      <MdOutlineRefresh className="me-1" />
      Rescan
    </span>
  );
}

export function JobActionsBar({ job, refetch }) {
  // routers
  const navigate = useNavigate();

  // callbacks
  const onDeleteBtnClick = async () => {
    const success = await deleteJob(job.id);
    if (!success) return;
    addToast("Redirecting...", null, "secondary");
    setTimeout(() => navigate(-1), 250);
  };

  const onDownloadSampleBtnClick = async () => {
    const blob = await downloadJobSample(job.id);
    if (!blob) return;
    // create URL blob and a hidden <a> tag to serve file for download
    const fileLink = document.createElement("a");
    fileLink.href = window.URL.createObjectURL(blob);
    fileLink.rel = "noopener,noreferrer";
    if (job?.file_name) {
      // it forces the name of the downloaded file
      fileLink.download = `${job.file_name}`;
    }
    // triggers the click event
    fileLink.click();
  };

  const onViewRawJsonBtnClick = async () => {
    addToast(
      "Link will be opened in a new tab shortly...",
      null,
      "spinner",
      false,
      2000,
    );
    const url = window.URL.createObjectURL(
      new Blob([JSON.stringify(job, null, 2)], {
        type: "application/json",
      }),
    );
    setTimeout(() => window.open(url, "rel=noopener,noreferrer"), 250);
  };
  const shareText = `Checkout this job (#${job.id}, ${
    job.is_sample ? job.file_name : job.observable_name
  }) on IntelOwl`;

  const handleRetry = async () => {
    const formValues = {
      ...job,
      check: "force_new",
      classification: job.observable_classification,
      tlp: job.tlp,
      observable_names: [job.observable_name],
      analyzers: job.analyzers_requested,
      connectors: job.connectors_requested,
      runtime_configuration: job.runtime_configuration,
      tags_labels: job.tags.map((optTag) => optTag.label),
      playbook: job.playbook_requested,
      scan_mode: scanMode.FORCE_NEW_ANALYSIS,
    };

    addToast("Retrying the same job...", null, "spinner", false, 2000);
    if (job.playbook_to_execute) {
      console.debug("retrying Playbook");
      const jobId = await createPlaybookJob(formValues).then(refetch);
      setTimeout(
        () => navigate(`/jobs/${jobId[0]}/${jobResultSection.VISUALIZER}/`),
        1000,
      );
    } else {
      console.debug("retrying Job");
      const jobId = await createJob(formValues).then(refetch);
      setTimeout(
        () => navigate(`/jobs/${jobId[0]}/${jobResultSection.VISUALIZER}/`),
        1000,
      );
    }
  };

  const commentIcon = () => <CommentIcon commentNumber={job.comments.length} />;
  return (
    <ContentSection className="d-inline-flex me-2">
      <IconButton
        id="commentbtn"
        Icon={commentIcon}
        size="sm"
        color="darker"
        className="me-2"
        onClick={() => navigate(`/jobs/${job.id}/comments`)}
        title="Comments"
        titlePlacement="top"
      />
      {job.permissions?.delete && (
        <IconButton
          id="deletejobbtn"
          Icon={DeleteIcon}
          size="sm"
          color="darker"
          className="me-2"
          onClick={onDeleteBtnClick}
          title="Delete Job"
          titlePlacement="top"
        />
      )}
      <IconButton
        id="rescanbtn"
        Icon={retryJobIcon}
        onClick={handleRetry}
        color="light"
        size="xs"
        title="Force run the same analysis"
        titlePlacement="top"
        className="me-2"
      />

      <SaveAsPlaybookButton job={job} />
      {job?.is_sample && (
        <Button
          size="sm"
          color="secondary"
          className="me-2"
          onClick={onDownloadSampleBtnClick}
        >
          <FaFileDownload />
          &nbsp;Sample
        </Button>
      )}
      <Button size="sm" color="darker" onClick={onViewRawJsonBtnClick}>
        <VscJson />
        &nbsp;Raw JSON
      </Button>
      <SocialShareBtn
        id="analysis-actions-share"
        url={window.location.href}
        text={shareText}
        longtext={shareText}
      />
    </ContentSection>
  );
}

export function JobInfoCard({ job }) {
  const process_time_mmss = new Date(job.process_time * 1000)
    .toISOString()
    .substring(14, 19);

  // local state
  const [isOpen, setIsOpen] = React.useState(false);

  return (
    <div id="JobInfoCardSection">
      <ContentSection className="mb-0 bg-darker">
        <Row>
          <Col
            className="d-flex-start-start justify-content-center offset-md-1"
            sm={12}
            md={10}
          >
            <h3>
              {job.is_sample ? (
                <VscFile className="me-1" />
              ) : (
                <VscGlobe className="me-1" />
              )}

              {job.is_sample ? (
                <CopyToClipboardButton
                  showOnHover
                  id="file_name"
                  text={job.file_name}
                >
                  {job.file_name}
                </CopyToClipboardButton>
              ) : (
                <CopyToClipboardButton
                  showOnHover
                  id="observable_name"
                  text={job.observable_name}
                >
                  {job.observable_name}
                </CopyToClipboardButton>
              )}
            </h3>
            <Badge className="ms-1 float-end" color="info">
              {job.is_sample
                ? `file: ${job.file_mimetype}`
                : job.observable_classification}
            </Badge>
          </Col>
          <Col sm={12} md={1} className="d-flex justify-content-end">
            <Button
              className="bg-darker border-0"
              onClick={() => setIsOpen(!isOpen)}
              id="JobInfoCardDropDown"
            >
              <ArrowToggleIcon isExpanded={isOpen} />
            </Button>
            <UncontrolledTooltip placement="left" target="JobInfoCardDropDown">
              Toggle Job Metadata
            </UncontrolledTooltip>
          </Col>
        </Row>
      </ContentSection>
      <Collapse isOpen={isOpen} id="JobInfoCardCollapse">
        <ContentSection className="border-top-0 bg-body ps-0 pe-1 py-1">
          <ListGroup
            horizontal
            className="align-items-start flex-wrap flex-lg-nowrap"
          >
            {[
              ["Status", <StatusTag status={job.status} />],
              ["TLP", <TLPTag value={job.tlp} />],
              ["User", job.user?.username],
              ["MD5", job.md5],
              ["Process Time (mm:ss)", process_time_mmss],
              [
                "Start Time",
                <DateHoverable
                  id={`overview-received_request_time__${job.id}`}
                  value={job.received_request_time}
                  format="hh:mm:ss a MMM do, yyyy"
                />,
              ],
              [
                "End Time",
                job.finished_analysis_time ? (
                  <DateHoverable
                    id={`overview-finished_analysis_time__${job.id}`}
                    value={job.finished_analysis_time}
                    format="hh:mm:ss a MMM do, yyyy"
                  />
                ) : (
                  "-"
                ),
              ],
            ].map(([key, value]) => (
              <ListGroupItem key={key}>
                <small className="fw-bold text-light">{key}</small>
                <div className="bg-dark p-1 text-light">{value}</div>
              </ListGroupItem>
            ))}
          </ListGroup>
          <ListGroup
            horizontal
            className="align-items-start flex-wrap flex-lg-nowrap"
          >
            {[
              [
                "Tags",
                job.tags.map((tag) => (
                  <JobTag key={tag.label} tag={tag} className="me-2" />
                )),
              ],
              [
                "Error(s)",
                <ul className="text-danger">
                  {job.errors.map((error) => (
                    <li>{error}</li>
                  ))}
                </ul>,
              ],
              [
                "Playbook",
                <PlaybookTag
                  key={job.playbook_to_execute}
                  playbook={job.playbook_to_execute}
                  className="mr-2"
                />,
              ],
            ].map(([key, value]) => (
              <ListGroupItem key={key}>
                <small className="fw-bold text-light">{key}</small>
                <div className="bg-dark p-1">{value}</div>
              </ListGroupItem>
            ))}
          </ListGroup>
        </ContentSection>
      </Collapse>
    </div>
  );
}

export function reportedVisualizerNumber(
  visualizersReportedList,
  visualizersToExecute,
) {
  /**
   * Return the number of visualizer in the final statuses
   */
  let visualizersNumber = 0;
  visualizersToExecute.forEach((visualizer) => {
    // count reports that have 'config' === 'visualizer' (pages from the same visualizer) and are in a final statuses
    let count = 0;
    visualizersReportedList.forEach((report) => {
      if (
        report.config === visualizer &&
        Object.values(pluginFinalStatuses).includes(report.status)
      )
        count += 1;
    });
    // reports relating to pages from the same visualizer are counted only once
    if (count === visualizersToExecute.length) visualizersNumber += 1;
  });
  return visualizersNumber;
}

export function reportedPluginNumber(pluginList) {
  /**
   * Return the number of plugin in the final statuses
   */
  return pluginList
    .map((report) => report.status)
    .filter((status) => Object.values(pluginFinalStatuses).includes(status))
    .length;
}

export function JobIsRunningAlert({ job }) {
  // number of analyzers/connectors/visualizers reported (status: killed/succes/failed)
  const analizersReported = reportedPluginNumber(job.analyzer_reports);
  const connectorsReported = reportedPluginNumber(job.connector_reports);
  const pivotsReported = reportedPluginNumber(job.pivot_reports);
  const visualizersReported = reportedVisualizerNumber(
    job.visualizer_reports,
    job.visualizers_to_execute,
  );

  /* Check if analyzers/connectors/visualizers are completed
    The analyzers are completed from the "analyzers_completed" status (index=3) to the last status 
    The connectors are completed from the "connectors_completed" status (index=5) to the last status 
    The visualizers are completed from the "visualizers_completed" status (index=7) to the last status 
  */
  const analyzersCompleted = Object.values(jobStatuses)
    .slice(3)
    .includes(job.status);
  const connectorsCompleted = Object.values(jobStatuses)
    .slice(5)
    .includes(job.status);
  const pivotsCompleted = Object.values(jobStatuses)
    .slice(7)
    .includes(job.status);
  const visualizersCompleted = Object.values(jobStatuses)
    .slice(9)
    .includes(job.status);

  const alertElements = [
    {
      step: 1,
      type: "ANALYZERS",
      completed:
        analizersReported === job.analyzers_to_execute.length &&
        analyzersCompleted,
      report: `${analizersReported}/${job.analyzers_to_execute.length}`,
    },
    {
      step: 2,
      type: "CONNECTORS",
      completed:
        connectorsReported === job.connectors_to_execute.length &&
        connectorsCompleted,
      report: `${connectorsReported}/${job.connectors_to_execute.length}`,
    },
    {
      step: 3,
      type: "PIVOTS",
      completed:
        pivotsReported === job.pivots_to_execute.length && pivotsCompleted,
      report: `${pivotsReported}/${job.pivots_to_execute.length}`,
    },
    {
      step: 4,
      type: "VISUALIZERS",
      completed:
        visualizersReported === job.visualizers_to_execute.length &&
        visualizersCompleted,
      report: `${visualizersReported}/${job.visualizers_to_execute.length}`,
    },
  ];

  return (
    <Fade className="d-flex-center mx-auto">
      <IconAlert
        id="jobisrunningalert-iconalert"
        color="info"
        className="text-info text-center"
      >
        <h6>
          This job is currently <strong className="text-accent">running</strong>
          .
        </h6>
        {alertElements.map((element) => (
          <div className="text-white">
            STEP {element.step}: {element.type} RUNNING -
            <strong
              className={`text-${element.completed ? "success" : "info"}`}
            >
              &nbsp;reported {element.report}
            </strong>
          </div>
        ))}
        {job.permissions?.kill && (
          <IconButton
            id="jobisrunningalert-iconbutton"
            Icon={MdPauseCircleOutline}
            size="xs"
            title="Stop Job Process"
            color="danger"
            titlePlacement="top"
            onClick={() => killJob(job.id)}
            className="mt-2"
          />
        )}
        <div className="text-gray">
          The page will auto-refresh once the analysis completes. You can either
          wait here or come back later and check.
        </div>
      </IconAlert>
    </Fade>
  );
}

export function ReportedPluginTooltip({ id, pluginName }) {
  return (
    <UncontrolledTooltip placement="top" target={id}>
      {pluginName} reported / {pluginName} executed
    </UncontrolledTooltip>
  );
}

JobActionsBar.propTypes = {
  job: PropTypes.object.isRequired,
};

JobInfoCard.propTypes = {
  job: PropTypes.object.isRequired,
};

JobIsRunningAlert.propTypes = {
  job: PropTypes.object.isRequired,
};
