import React from "react";
import PropTypes from "prop-types";
import { Button, ListGroup, ListGroupItem, Badge, Fade } from "reactstrap";
import { useHistory } from "react-router-dom";
import { VscGlobe, VscFile, VscJson } from "react-icons/vsc";
import { FaFileDownload } from "react-icons/fa";
import { MdDeleteOutline, MdPauseCircleOutline } from "react-icons/md";

import {
  ContentSection,
  MomentHoverable,
  SocialShareBtn,
  IconAlert,
  IconButton,
  addToast
} from "@certego/certego-ui";

import { JobTag, StatusTag, TLPTag } from "../../common";
import { downloadJobSample, deleteJob, killJob } from "./api";

export function JobActionsBar({ job, }) {
  // routers
  const history = useHistory();

  // callbacks
  const onDeleteBtnClick = async () => {
    const success = await deleteJob(job.id);
    if (!success) return;
    addToast("Redirecting...", null, "secondary");
    setTimeout(history.goBack, 250);
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
      2000
    );
    const url = window.URL.createObjectURL(
      new Blob([JSON.stringify(job, null, 2)], {
        type: "application/json",
      })
    );
    setTimeout(() => window.open(url, "rel=noopener,noreferrer"), 250);
  };
  const shareText = `Checkout this job (#${job.id}, ${
    job.is_sample ? job.file_name : job.observable_name
  }) on IntelOwl`;

  return (
    <ContentSection className="d-inline-flex">
      <IconButton
        id="deletejobbtn"
        Icon={() => <MdDeleteOutline className="text-danger" />}
        size="sm"
        color="darker"
        className="mr-2"
        onClick={onDeleteBtnClick}
        title="Delete Job"
        titlePlacement="top"
      />
      {job?.is_sample && (
        <Button
          size="sm"
          color="darker"
          className="mr-2"
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

export function JobInfoCard({ job, }) {
  return (
    <>
      <ContentSection className="mb-0 bg-darker d-flex-center">
        <div className="d-flex-start-start">
          <h3>
            {job.is_sample ? (
              <VscFile className="mr-1" />
            ) : (
              <VscGlobe className="mr-1" />
            )}
            {job.is_sample ? job.file_name : job.observable_name}
          </h3>
          <Badge className="ml-1 float-right" color="info">
            {job.is_sample
              ? `file: ${job.file_mimetype}`
              : job.observable_classification}
          </Badge>
        </div>
      </ContentSection>
      <ContentSection className="border-top-0 bg-body pl-0 pr-1 py-1">
        <ListGroup
          horizontal
          className="align-items-start flex-wrap flex-lg-nowrap"
        >
          {[
            ["Status", <StatusTag status={job.status} />],
            ["TLP", <TLPTag value={job.tlp} />],
            ["User", job.user?.username],
            ["MD5", job.md5],
            ["Process Time (s)", job.process_time],
            [
              "Start Time",
              <MomentHoverable
                id={`overview-received_request_time__${job.id}`}
                value={job.received_request_time}
                format="h:mm A MMM Do, YYYY"
              />,
            ],
            [
              "End Time",
              <MomentHoverable
                id={`overview-finished_analysis_time__${job.id}`}
                value={job.finished_analysis_time}
                format="h:mm A MMM Do, YYYY"
              />,
            ],
          ].map(([key, value]) => (
            <ListGroupItem key={key}>
              <small className="font-weight-bold">{key}</small>
              <div className="bg-dark p-1">{value}</div>
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
                <JobTag key={tag.label} tag={tag} className="mr-2" />
              )),
            ],
            [
              "Error(s)",
              <textarea
                disabled
                value={job.errors}
                className="text-danger"
                hidden={!job.errors.length}
              />,
            ],
          ].map(([key, value]) => (
            <ListGroupItem key={key}>
              <small className="font-weight-bold">{key}</small>
              <div className="bg-dark p-1">{value}</div>
            </ListGroupItem>
          ))}
        </ListGroup>
      </ContentSection>
    </>
  );
}

export function JobIsRunningAlert({ job, }) {
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
        <IconButton
          id="jobisrunningalert-iconbutton"
          Icon={MdPauseCircleOutline}
          size="xs"
          title="Stop Job Process"
          color="danger"
          titlePlacement="top"
          onClick={() => killJob(job.id)}
        />
        <div className="text-gray">
          The page will auto-refresh once the analysis completes. You can either
          wait here or come back later and check.
        </div>
      </IconAlert>
    </Fade>
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
