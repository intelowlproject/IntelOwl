import React from "react";
import axios from "axios";
import { IoMdWarning } from "react-icons/io";

import { addToast, confirm } from "@certego/certego-ui";

import { JOB_BASE_URI } from "../../../constants/apiURLs";

// constants

const areYouSureConfirmDialog = (opName) =>
  confirm({
    title: (
      <div className="d-flex-start-center">
        <IoMdWarning className="text-warning" />
        <span className="ms-1">Confirm</span>
      </div>
    ),
    message: (
      <div className="text-wrap">
        <h6 className="text-muted">Operation:</h6>
        <h6 className="text-center text-ul fst-italic">{opName}</h6>
        <hr className="bg-dark" />
        <span className="">Are you sure ?</span>
      </div>
    ),
    confirmColor: "secondary",
    cancelColor: "link text-gray",
  });

export async function downloadJobSample(jobId) {
  let blob;
  try {
    const resp = await axios.get(`${JOB_BASE_URI}/${jobId}/download_sample`, {
      responseType: "blob",
    });
    blob = new Blob([resp.data]);
  } catch (error) {
    addToast("Failed", error.parsedMsg, "warning");
  }
  return blob;
}

export async function killJob(jobId) {
  const sure = await areYouSureConfirmDialog(`kill job #${jobId}`);
  if (!sure) return Promise.reject();
  let success = false;
  try {
    const response = await axios.patch(`${JOB_BASE_URI}/${jobId}/kill`);
    success = response.status === 204;
    if (success) {
      addToast(<span>Sent kill request for job #{jobId}</span>, null, "info");
    }
  } catch (error) {
    addToast(
      <span>
        Failed. Operation: <em>kill job #{jobId}</em>
      </span>,
      error.parsedMsg,
      "warning",
    );
  }
  return success;
}

export async function deleteJob(jobId) {
  const sure = await areYouSureConfirmDialog(`delete job #${jobId}`);
  if (!sure) return Promise.reject();
  let success = false;
  try {
    const response = await axios.delete(`${JOB_BASE_URI}/${jobId}`);
    success = response.status === 204;
    if (success) {
      addToast(<span>Deleted Job #{jobId}</span>, null, "info");
    }
  } catch (error) {
    addToast(
      <span>
        Failed. Operation: <em>delete job #{jobId}</em>
      </span>,
      error.parsedMsg,
      "warning",
    );
  }
  return success;
}

export async function killPlugin(jobId, plugin) {
  const sure = await areYouSureConfirmDialog(
    `kill ${plugin.type} '${plugin.name}'`,
  );
  if (!sure) return Promise.reject();
  let success = false;
  try {
    const response = await axios.patch(
      `${JOB_BASE_URI}/${jobId}/${plugin.type}/${plugin.id}/kill`,
    );
    success = response.status === 204;
    if (success) {
      addToast(
        <span>
          Kill request sent for {plugin.type} <em>{plugin.name}</em>
        </span>,
        null,
        "info",
      );
    }
  } catch (error) {
    addToast(
      <span>
        Failed. Operation: kill {plugin.type} <em>{plugin.name}</em>
      </span>,
      error.parsedMsg,
      "warning",
    );
  }
  return success;
}

export async function retryPlugin(jobId, plugin) {
  const sure = await areYouSureConfirmDialog(
    `retry ${plugin.type} '${plugin.name}'`,
  );
  if (!sure) return Promise.reject();
  let success = false;
  try {
    const response = await axios.patch(
      `${JOB_BASE_URI}/${jobId}/${plugin.type}/${plugin.id}/retry`,
    );
    success = response.status === 204;
    if (success) {
      addToast(
        <span>
          Retry request sent for {plugin.type} <em>{plugin.name}</em>
        </span>,
        null,
        "info",
      );
    }
  } catch (error) {
    addToast(
      <span>
        Failed. Operation: retry {plugin.type} <em>{plugin.name}</em>
      </span>,
      error.parsedMsg,
      "warning",
    );
  }
  return success;
}
