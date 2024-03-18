import React from "react";
import axios from "axios";

import { addToast } from "@certego/certego-ui";

import { ANALYSIS_BASE_URI, JOB_BASE_URI } from "../../../constants/apiURLs";
import { areYouSureConfirmDialog } from "../../common/areYouSureConfirmDialog";

export async function createAnalysis() {
  let success = false;
  const data = { name: "Custom analysis", description: "" };
  try {
    const response = await axios.post(`${ANALYSIS_BASE_URI}`, data);
    success = response.status === 201;
    if (success) {
      addToast(
        <span>Created Analysis #{response.data.id}</span>,
        null,
        "success",
      );
      return response.data.id;
    }
  } catch (error) {
    addToast(
      <span>
        Failed. Operation: <em>create new analysis</em>
      </span>,
      error.parsedMsg,
      "warning",
    );
  }
  return success;
}

export async function deleteAnalysis(analysisId) {
  let success = false;
  try {
    const response = await axios.delete(`${ANALYSIS_BASE_URI}/${analysisId}`);
    success = response.status === 204;
    if (success) {
      addToast(<span>Deleted Analysis #{analysisId}</span>, null, "info");
    }
  } catch (error) {
    addToast(
      <span>
        Failed. Operation: <em>delete analysis #{analysisId}</em>
      </span>,
      error.parsedMsg,
      "warning",
    );
  }
  return success;
}

export async function updateAnalysis(analysisId, data) {
  let success = false;
  try {
    const response = await axios.patch(
      `${ANALYSIS_BASE_URI}/${analysisId}`,
      data,
    );
    success = response.status === 200;
    if (success) {
      addToast(<span>Updated Analysis #{analysisId}</span>, null, "info");
    }
  } catch (error) {
    addToast(
      <span>
        Failed. Operation: <em>update analysis #{analysisId}</em>
      </span>,
      error.parsedMsg,
      "warning",
    );
  }
  return success;
}

export async function addJob(analysisId, jobId) {
  let success = false;
  const data = { job: jobId };
  try {
    const response = await axios.post(
      `${ANALYSIS_BASE_URI}/${analysisId}/add_job`,
      data,
    );
    success = response.status === 200;
    if (success) {
      addToast(
        <span>
          Job #{jobId} added to the Analysis #{analysisId}
        </span>,
        null,
        "success",
      );
    }
  } catch (error) {
    addToast(
      <span>
        Failed. Operation:{" "}
        <em>
          add job #{jobId} to the analysis #{analysisId}
        </em>
      </span>,
      error.parsedMsg,
      "warning",
    );
  }
  return success;
}

export async function removeJob(analysisId, jobId) {
  let success = false;
  try {
    const response = await axios.post(
      `${ANALYSIS_BASE_URI}/${analysisId}/remove_job`,
      { job: jobId },
    );
    success = response.status === 200;
    if (success) {
      addToast(
        <span>
          Job #{jobId} removed from the Analysis #{analysisId}
        </span>,
        null,
        "success",
      );
    }
  } catch (error) {
    addToast(
      <span>
        Failed. Operation:{" "}
        <em>
          remove job #{jobId} from the analysis #{analysisId}
        </em>
      </span>,
      error.parsedMsg,
      "warning",
    );
  }
  return success;
}

export async function addExistingJob(jobToAdd, currentAnalysisId) {
  let success = false;
  let jobAnalysisId = null;
  try {
    const response = await axios.get(`${JOB_BASE_URI}/${jobToAdd}`);
    success = response.status === 200;
    if (success) {
      jobAnalysisId = response.data.analysis;
    }
  } catch (error) {
    addToast(
      <span>
        Failed. Operation: <em>add existing job</em>
      </span>,
      error.parsedMsg,
      "warning",
    );
    return success;
  }

  // case 1 - Job is already part of this analysis
  if (jobAnalysisId === currentAnalysisId) {
    addToast(
      <span>
        Failed. Operation: <em>add existing job</em>
      </span>,
      "Job is already part of this analysis",
      "warning",
    );
  }
  // case 2 - job is already part of different analysis
  else if (jobAnalysisId) {
    const sure = await areYouSureConfirmDialog(
      `Remove job #${jobToAdd} from analysis #${jobAnalysisId} and add into analysis #${currentAnalysisId}`,
    );
    if (sure) {
      // remove job from previous analysis
      const isJobRemoved = await removeJob(jobAnalysisId, jobToAdd);
      if (isJobRemoved) {
        // add job into current analysis
        const isJobAdded = await addJob(currentAnalysisId, jobToAdd);
        return isJobAdded;
      }
      return isJobRemoved;
    }
  }
  // case 3 - job is not part of any analysis
  else {
    const isJobAdded = await addJob(currentAnalysisId, jobToAdd);
    return isJobAdded;
  }
  return false;
}
