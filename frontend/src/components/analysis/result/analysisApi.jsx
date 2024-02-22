import React from "react";
import axios from "axios";

import { addToast } from "@certego/certego-ui";

import { ANALYSIS_BASE_URI } from "../../../constants/apiURLs";
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
  const sure = await areYouSureConfirmDialog(`delete analysis #${analysisId}`);
  if (!sure) return Promise.reject();
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
