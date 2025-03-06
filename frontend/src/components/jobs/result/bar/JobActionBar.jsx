import React from "react";
import PropTypes from "prop-types";
import { Button } from "reactstrap";
import { useNavigate } from "react-router-dom";
import { FaFileDownload } from "react-icons/fa";

import { ContentSection, IconButton, addToast } from "@certego/certego-ui";

import { SaveAsPlaybookButton } from "./SaveAsPlaybooksForm";

import { downloadJobSample, deleteJob, rescanJob } from "../jobApi";
import { JobResultSections } from "../../../../constants/miscConst";
import {
  DeleteIcon,
  CommentIcon,
  retryJobIcon,
  downloadReportIcon,
} from "../../../common/icon/actionIcons";
import { fileDownload } from "../../../../utils/files";

export function JobActionsBar({ job }) {
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
    let filename = "file";
    if (job?.file_name) {
      // it forces the name of the downloaded file
      filename = `${job.file_name}`;
    }
    fileDownload(blob, filename);
  };

  const handleRetry = async () => {
    addToast("Retrying the same job...", null, "spinner", false, 2000);
    const newJobId = await rescanJob(job.id);
    if (newJobId) {
      setTimeout(
        () => navigate(`/jobs/${newJobId}/${JobResultSections.VISUALIZER}/`),
        1000,
      );
    }
  };

  const onDownloadReport = () => {
    if (job) {
      const blob = new Blob([JSON.stringify(job)], { type: "text/json" });
      if (!blob) return;
      fileDownload(blob, `job#${job.id}_report.json`);
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
        size="sm"
        title="Force run the same analysis"
        titlePlacement="top"
        className="me-2"
      />
      <SaveAsPlaybookButton job={job} />
      {job?.is_sample && (
        <Button
          size="sm"
          color="secondary"
          className="ms-2"
          onClick={onDownloadSampleBtnClick}
        >
          <FaFileDownload />
          &nbsp;Sample
        </Button>
      )}
      <IconButton
        id="downloadreportbtn"
        Icon={downloadReportIcon}
        size="sm"
        color="accent-2"
        className="ms-2"
        onClick={onDownloadReport}
        title="Download report in json format"
        titlePlacement="top"
      />
    </ContentSection>
  );
}

JobActionsBar.propTypes = {
  job: PropTypes.object.isRequired,
};
