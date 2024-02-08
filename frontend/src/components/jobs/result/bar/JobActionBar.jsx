import React from "react";
import PropTypes from "prop-types";
import { Button } from "reactstrap";
import { useNavigate } from "react-router-dom";
import { FaFileDownload } from "react-icons/fa";

import { ContentSection, IconButton, addToast } from "@certego/certego-ui";

import { SaveAsPlaybookButton } from "./SaveAsPlaybooksForm";

import { downloadJobSample, deleteJob } from "../jobApi";
import { createJob } from "../../../scan/scanApi";
import { ScanModesNumeric } from "../../../../constants/advancedSettingsConst";
import { JobResultSections } from "../../../../constants/miscConst";
import { DeleteIcon, CommentIcon, retryJobIcon } from "../utils/icons";

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

  const handleRetry = async () => {
    if (job.is_sample) {
      addToast(
        "Rescan File!",
        "It's not possible to repeat a sample analysis",
        "warning",
        false,
        2000,
      );
    } else {
      addToast("Retrying the same job...", null, "spinner", false, 2000);
      const jobId = await createJob(
        [job.observable_name],
        job.observable_classification,
        job.playbook_requested,
        job.analyzers_requested,
        job.connectors_requested,
        job.runtime_configuration,
        job.tags.map((optTag) => optTag.label),
        job.tlp,
        ScanModesNumeric.FORCE_NEW_ANALYSIS,
        0,
      );
      setTimeout(
        () => navigate(`/jobs/${jobId[0]}/${JobResultSections.VISUALIZER}/`),
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
        size="sm"
        title="Force run the same analysis"
        titlePlacement="top"
        className="me-2"
      />
      <SaveAsPlaybookButton job={job} />
      {job?.is_sample && (
        <Button size="sm" color="secondary" onClick={onDownloadSampleBtnClick}>
          <FaFileDownload />
          &nbsp;Sample
        </Button>
      )}
    </ContentSection>
  );
}

JobActionsBar.propTypes = {
  job: PropTypes.object.isRequired,
};
