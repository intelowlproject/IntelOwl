import React from "react";
import PropTypes from "prop-types";
import {
  DropdownToggle,
  DropdownMenu,
  DropdownItem,
  UncontrolledDropdown,
  Badge,
} from "reactstrap";
import { useNavigate } from "react-router-dom";
import { TiThMenu } from "react-icons/ti";
import { IoMdSave } from "react-icons/io";
import { IconButton, addToast } from "@certego/certego-ui";
import { MdDelete, MdOutlineRefresh, MdFileDownload } from "react-icons/md";
import { FaFileDownload } from "react-icons/fa";

import { downloadJobSample, deleteJob, rescanJob } from "../jobApi";
import {
  JobResultSections,
  Classifications,
} from "../../../../constants/miscConst";
import { CommentIcon } from "../../../common/icon/actionIcons";
import { fileDownload } from "../../../../utils/files";
import { PluginConfigModal } from "../../../plugins/PluginConfigModal";
import { PluginsTypes } from "../../../../constants/pluginConst";
import {
  AnalyzableOverviewButton,
  InvestigationOverviewButton,
  RelatedInvestigationButton,
} from "../utils/jobButtons";

export function JobActionsBar({ job, relatedInvestigationNumber }) {
  console.debug(job);
  // routers
  const navigate = useNavigate();
  // state
  const [showModalCreatePlaybook, setShowModalCreatePlaybook] =
    React.useState(false);

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
    <div className="d-inline-flex">
      {job?.investigation_id && (
        <InvestigationOverviewButton
          id={job.investigation_id}
          name={job.investigation_name}
        />
      )}
      <AnalyzableOverviewButton id={job.analyzable_id} />
      <div>
        <IconButton
          id="commentbtn"
          Icon={commentIcon}
          size="sm"
          color="gray"
          className="me-1 text-light"
          onClick={() => navigate(`/jobs/${job.id}/comments`)}
        />
        {job.comments.length > 0 && (
          <Badge color="light" className="badge-top-end-corner text-black">
            {job.comments.length}
          </Badge>
        )}
      </div>
      <UncontrolledDropdown inNavbar>
        <DropdownToggle nav className="text-center">
          <IconButton
            id="jobActions"
            Icon={TiThMenu}
            size="sm"
            color="light"
            title="Job actions"
            titlePlacement="top"
          />
        </DropdownToggle>
        <DropdownMenu end className="bg-dark" data-bs-popper>
          <RelatedInvestigationButton
            name={job.is_sample ? job.file_name : job.observable_name}
            relatedInvestigationNumber={relatedInvestigationNumber}
          />
          <DropdownItem divider />
          <DropdownItem
            onClick={onDownloadReport}
            className="d-flex align-items-center text-light"
          >
            <MdFileDownload className="me-1 text-advisory" />
            Download report
          </DropdownItem>
          {job?.is_sample && (
            <DropdownItem
              onClick={onDownloadSampleBtnClick}
              className=" d-flex align-items-center text-light"
            >
              <FaFileDownload className="me-1 text-advisory" />
              Download sample
            </DropdownItem>
          )}
          <DropdownItem
            onClick={() => setShowModalCreatePlaybook(true)}
            className=" d-flex align-items-center text-light"
          >
            <IoMdSave className="me-1 text-advisory" />
            Save as playbook
            <PluginConfigModal
              pluginConfig={{
                analyzers: job?.analyzers_to_execute,
                connectors: job?.connectors_to_execute,
                pivots: job?.pivots_to_execute,
                type: [
                  job?.is_sample
                    ? Classifications.FILE
                    : job?.observable_classification,
                ],
                runtimeConfiguration: job?.runtime_configuration,
                tags: job?.tags.map((tag) => tag?.label),
                tlp: job?.tlp,
                scan_mode: job?.scan_mode,
                scan_check_time: job?.scan_check_time,
              }}
              pluginType={PluginsTypes.PLAYBOOK}
              toggle={setShowModalCreatePlaybook}
              isOpen={showModalCreatePlaybook}
            />
          </DropdownItem>
          <DropdownItem divider />
          <DropdownItem
            onClick={handleRetry}
            className=" d-flex align-items-center text-light"
          >
            <MdOutlineRefresh className="me-1 text-accent" />
            Rescan
          </DropdownItem>
          {job.permissions?.delete && (
            <DropdownItem
              onClick={onDeleteBtnClick}
              className=" d-flex align-items-center text-light"
            >
              <MdDelete className="text-danger me-1" />
              Delete
            </DropdownItem>
          )}
        </DropdownMenu>
      </UncontrolledDropdown>
    </div>
  );
}

JobActionsBar.propTypes = {
  job: PropTypes.object.isRequired,
  relatedInvestigationNumber: PropTypes.number.isRequired,
};
