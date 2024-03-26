import React from "react";
import axios from "axios";

import { addToast } from "@certego/certego-ui";

import {
  INVESTIGATION_BASE_URI,
  JOB_BASE_URI,
} from "../../../constants/apiURLs";
import { areYouSureConfirmDialog } from "../../common/areYouSureConfirmDialog";
import { prettifyErrors } from "../../../utils/api";

export async function createInvestigation() {
  let success = false;
  const data = {
    name: "Custom investigation",
    description: "",
    for_organization: true,
  };
  try {
    const response = await axios.post(`${INVESTIGATION_BASE_URI}`, data);
    success = response.status === 201;
    if (success) {
      addToast(
        <span>Created Investigation #{response.data.id}</span>,
        null,
        "success",
      );
      return response.data.id;
    }
  } catch (error) {
    addToast(
      "Failed to create new investigation",
      prettifyErrors(error),
      "warning",
    );
  }
  return success;
}

export async function deleteInvestigation(investigationId) {
  let success = false;
  try {
    const response = await axios.delete(
      `${INVESTIGATION_BASE_URI}/${investigationId}`,
    );
    success = response.status === 204;
    if (success) {
      addToast(
        <span>Deleted Investigation #{investigationId}</span>,
        null,
        "info",
      );
    }
  } catch (error) {
    addToast(
      `Failed to delete investigation #${investigationId}`,
      prettifyErrors(error),
      "warning",
    );
  }
  return success;
}

export async function updateInvestigation(investigationId, data) {
  let success = false;
  try {
    const response = await axios.patch(
      `${INVESTIGATION_BASE_URI}/${investigationId}`,
      data,
    );
    success = response.status === 200;
    if (success) {
      addToast(
        <span>Updated Investigation #{investigationId}</span>,
        null,
        "info",
      );
    }
  } catch (error) {
    addToast(
      `Failed to update investigation #${investigationId}`,
      prettifyErrors(error),
      "warning",
    );
  }
  return success;
}

export async function addJob(investigationId, jobId) {
  let success = false;
  const data = { job: jobId };
  try {
    const response = await axios.post(
      `${INVESTIGATION_BASE_URI}/${investigationId}/add_job`,
      data,
    );
    success = response.status === 200;
    if (success) {
      addToast(
        <span>
          Job #{jobId} added to the Investigation #{investigationId}
        </span>,
        null,
        "success",
      );
    }
  } catch (error) {
    addToast(
      `Failed to add job #${jobId} to the investigation #${investigationId}`,
      prettifyErrors(error),
      "warning",
    );
  }
  return success;
}

export async function removeJob(investigationId, jobId) {
  let success = false;
  try {
    const response = await axios.post(
      `${INVESTIGATION_BASE_URI}/${investigationId}/remove_job`,
      { job: jobId },
    );
    success = response.status === 200;
    if (success) {
      addToast(
        <span>
          Job #{jobId} removed from the Investigation #{investigationId}
        </span>,
        null,
        "success",
      );
    }
  } catch (error) {
    addToast(
      `Failed to remove job #${jobId} from the investigation #${investigationId}`,
      prettifyErrors(error),
      "warning",
    );
  }
  return success;
}

export async function addExistingJob(jobToAdd, currentInvestigationId) {
  let success = false;
  let jobInvestigationId = null;
  try {
    const response = await axios.get(`${JOB_BASE_URI}/${jobToAdd}`);
    success = response.status === 200;
    if (success) {
      jobInvestigationId = response.data.investigation;
    }
  } catch (error) {
    addToast(
      `Failed to add job #${jobToAdd} to the investigation #${currentInvestigationId}`,
      prettifyErrors(error),
      "warning",
    );
    return success;
  }

  // case 1 - Job is already part of this investigation
  if (jobInvestigationId === currentInvestigationId) {
    addToast(
      `Failed to add job #${jobToAdd} to the investigation #${currentInvestigationId}`,
      "Job is already part of this investigation",
      "warning",
    );
  }
  // case 2 - job is already part of different investigation
  else if (jobInvestigationId) {
    const sure = await areYouSureConfirmDialog(
      `Remove job #${jobToAdd} from investigation #${jobInvestigationId} and add into investigation #${currentInvestigationId}`,
    );
    if (sure) {
      // remove job from previous investigation
      const isJobRemoved = await removeJob(jobInvestigationId, jobToAdd);
      if (isJobRemoved) {
        // add job into current investigation
        const isJobAdded = await addJob(currentInvestigationId, jobToAdd);
        return isJobAdded;
      }
      return isJobRemoved;
    }
  }
  // case 3 - job is not part of any investigation
  else {
    const isJobAdded = await addJob(currentInvestigationId, jobToAdd);
    return isJobAdded;
  }
  return false;
}
