/* eslint-disable no-unused-vars */
/* eslint-disable no-console */
/* eslint-disable react/prop-types */
/* eslint-disable camelcase */
import React from "react";
import PropTypes from "prop-types";
import { Button, ListGroup, ListGroupItem, Badge, Fade } from "reactstrap";
import { useNavigate } from "react-router-dom";
import { VscGlobe, VscFile, VscJson } from "react-icons/vsc";
import { FaFileDownload } from "react-icons/fa";
import {
  MdDeleteOutline,
  MdPauseCircleOutline,
  MdOutlineRefresh,
} from "react-icons/md";

import {
  ContentSection,
  DateHoverable,
  SocialShareBtn,
  IconAlert,
  IconButton,
  addToast,
} from "@certego/certego-ui";

import { SaveAsPlaybookButton } from "./SaveAsPlaybooksForm";

import { JobTag, PlaybookTag, StatusTag, TLPTag } from "../../../common";
import {
  downloadJobSample,
  deleteJob,
  killJob,
  retryJob,
  retryPlugin,
} from "../api";

function DeleteIcon() {
  return <MdDeleteOutline className="text-danger" />;
}

export function JobActionsBar({ job, refetch }) {
  // routers
  const navigate = useNavigate();

  console.log(job.analyzers_to_execute);

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
        Icon={MdOutlineRefresh}
        onClick={() => {
          job.analyzers_to_execute.map((analyzername) => {
            retryJob(job.id, "analyzer", analyzername).then(refetch);
            return true;
          });
        }}
        color="light"
        size="xs"
        title="run"
        titlePlacement="top"
        className="border-0"
        style={{ marginRight: 10 }}
      />

      <SaveAsPlaybookButton jobId={job.id} />
      {job?.is_sample && (
        <Button
          size="sm"
          color="darker"
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

  return (
    <>
      <ContentSection className="mb-0 bg-darker d-flex-center">
        <div className="d-flex-start-start">
          <h3>
            {job.is_sample ? (
              <VscFile className="me-1" />
            ) : (
              <VscGlobe className="me-1" />
            )}
            {job.is_sample ? job.file_name : job.observable_name}
          </h3>
          <Badge className="ms-1 float-end" color="info">
            {job.is_sample
              ? `file: ${job.file_mimetype}`
              : job.observable_classification}
          </Badge>
        </div>
      </ContentSection>
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
              <textarea
                disabled
                value={job.errors}
                className="text-danger"
                hidden={!job.errors.length}
              />,
            ],
            [
              "Playbook(s)",
              job.playbooks_to_execute.map((playbook) => (
                <PlaybookTag
                  key={playbook}
                  playbook={playbook}
                  className="mr-2"
                />
              )),
            ],
          ].map(([key, value]) => (
            <ListGroupItem key={key}>
              <small className="fw-bold text-light">{key}</small>
              <div className="bg-dark p-1">{value}</div>
            </ListGroupItem>
          ))}
        </ListGroup>
      </ContentSection>
    </>
  );
}

export function JobIsRunningAlert({ job }) {
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
        {job.permissions?.kill && (
          <IconButton
            id="jobisrunningalert-iconbutton"
            Icon={MdPauseCircleOutline}
            size="xs"
            title="Stop Job Process"
            color="danger"
            titlePlacement="top"
            onClick={() => killJob(job.id)}
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

JobActionsBar.propTypes = {
  job: PropTypes.object.isRequired,
};

JobInfoCard.propTypes = {
  job: PropTypes.object.isRequired,
};

JobIsRunningAlert.propTypes = {
  job: PropTypes.object.isRequired,
};
