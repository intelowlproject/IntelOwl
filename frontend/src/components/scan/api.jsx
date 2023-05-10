/* eslint-disable no-underscore-dangle */
import React from "react";
import axios from "axios";
import md5 from "md5";

import { ContentSection, readFileAsync, addToast } from "@certego/certego-ui";

import {
  ANALYZE_MULTIPLE_OBSERVABLE_URI,
  ASK_MULTI_ANALYSIS_AVAILABILITY_URI,
  ANALYZE_MULTIPLE_FILES_URI,
  API_BASE_URI,
  COMMENT_BASE_URI,
} from "../../constants/api";
import useRecentScansStore from "../../stores/useRecentScansStore";

const { append: appendToRecentScans } = useRecentScansStore.getState();

export async function createPlaybookJob(formValues) {
  // check existing
  if (formValues.check !== "force_new") {
    const jobId = await _askAnalysisAvailability(formValues);
    if (jobId) return Promise.resolve(jobId);
  }

  // new scan
  const resp =
    formValues.classification === "file"
      ? await _startPlaybookFile(formValues)
      : await _startPlaybookObservable(formValues);

  const playbooksRunning = new Set();
  const warnings = [];
  const respData = resp.data.results;

  respData.forEach((x) => {
    if (x.playbook_running) playbooksRunning.add(x.playbook_running);
    if (x.warnings) warnings.push(...x.warnings);
  });

  try {
    // handle response/error
    if (
      respData.every(
        (element) =>
          element.status === "accepted" || element.status === "running"
      )
    ) {
      const jobIds = respData.map((x) => parseInt(x.job_id, 10));
      jobIds.forEach((jobId) => {
        appendToRecentScans(jobId, "success");
      });
      addToast(
        `Created new Job with ID(s) #${jobIds.join(", ")}!`,
        <div>
          <ContentSection className="text-light">
            <strong>Playbooks:</strong>&nbsp;
            {Array.from(playbooksRunning)?.join(", ")}
          </ContentSection>
          {warnings.length > 0 && (
            <ContentSection className="bg-accent text-darker">
              <strong>Warnings:</strong>&nbsp;{warnings.join(", ")}
            </ContentSection>
          )}
        </div>,
        "success",
        true,
        10000
      );
      return Promise.resolve(jobIds);
    }
    // else
    addToast("Failed!", respData?.message, "danger");
    const error = new Error(`job status ${respData.status}`);
    return Promise.reject(error);
  } catch (e) {
    console.error(e);
    addToast("Failed!", e.parsedMsg, "danger");
    return Promise.reject(e);
  }
}

export async function createComment(formValues) {
  try {
    const resp = await axios.post(`${COMMENT_BASE_URI}`, formValues);

    return Promise.resolve(resp);
  } catch (e) {
    console.error(e);
    addToast("Failed!", e.parsedMsg, "danger");
    return Promise.reject(e);
  }
}

export async function deleteComment(commentId) {
  try {
    const resp = await axios.delete(`${COMMENT_BASE_URI}/${commentId}`);

    return Promise.resolve(resp);
  } catch (e) {
    console.error(e);
    addToast("Failed!", e.parsedMsg, "danger");
    return Promise.reject(e);
  }
}

export async function createJob(formValues) {
  try {
    // check existing
    if (formValues.check !== "force_new") {
      const jobId = await _askAnalysisAvailability(formValues);
      if (jobId) return Promise.resolve(jobId);
    }

    // new scan
    const resp =
      formValues.classification === "file"
        ? await _analyzeFile(formValues)
        : await _analyzeObservable(formValues);

    const respData = resp.data.results;
    const analyzersRunning = new Set();
    const connectorsRunning = new Set();
    const warnings = [];
    respData.forEach((x) => {
      if (x.analyzers_running)
        x.analyzers_running.forEach((analyzer) =>
          analyzersRunning.add(analyzer)
        );
      if (x.connectors_running)
        x.connectors_running.forEach((connector) =>
          connectorsRunning.add(connector)
        );
      if (x.warnings) warnings.push(...x.warnings);
    });
    // handle response/error
    if (
      respData.every(
        (element) =>
          element.status === "accepted" || element.status === "running"
      )
    ) {
      const jobIds = respData.map((x) => parseInt(x.job_id, 10));
      jobIds.forEach((jobId) => {
        appendToRecentScans(jobId, "success");
      });
      addToast(
        `Created new Job with ID(s) #${jobIds.join(", ")}!`,
        <div>
          <ContentSection className="text-light">
            <strong>Analyzers:</strong>&nbsp;
            {Array.from(analyzersRunning)?.join(", ")}
          </ContentSection>
          {connectorsRunning.length > 0 && (
            <ContentSection className="text-light">
              <strong>Connectors:</strong>&nbsp;
              {Array.from(connectorsRunning).join(", ")}
            </ContentSection>
          )}
          {warnings.length > 0 && (
            <ContentSection className="bg-accent text-darker">
              <strong>Warnings:</strong>&nbsp;{warnings.join(", ")}
            </ContentSection>
          )}
        </div>,
        "success",
        true,
        10000
      );
      return Promise.resolve(jobIds);
    }

    // else
    addToast("Failed!", respData?.message, "danger");
    const error = new Error(`job status ${respData.status}`);
    return Promise.reject(error);
  } catch (e) {
    console.error(e);
    addToast("Failed!", e.parsedMsg, "danger");
    return Promise.reject(e);
  }
}

async function _askAnalysisAvailability(formValues) {
  console.debug("_askAnalysisAvailability - formValues");
  console.debug(formValues);

  const payload = [];
  const minutesAgo = formValues.hoursAgo * 60;

  if (formValues.classification === "file") {
    const promises = [];
    Array.from(formValues.files).forEach((file) => {
      const body = {
        analyzers: formValues.analyzers,
        playbooks: formValues.playbooks,
        md5: md5(readFileAsync(file)),
      };
      if (minutesAgo) {
        body.minutes_ago = minutesAgo;
      }
      promises.push(body.md5);
      if (formValues.check === "running_only") {
        body.running_only = "True";
      }
      payload.push(body);
    });
    await Promise.all(promises);
  } else {
    formValues.observable_names.forEach((ObservableName) => {
      const body = {
        analyzers: formValues.analyzers,
        playbooks: formValues.playbooks,
        md5: md5(ObservableName),
      };
      if (minutesAgo) {
        body.minutes_ago = minutesAgo;
      }
      if (formValues.check === "running_only") {
        body.running_only = "True";
      }
      payload.push(body);
    });
  }

  console.debug("_askAnalysisAvailability - payload");
  console.debug(payload);
  try {
    const response = await axios.post(
      ASK_MULTI_ANALYSIS_AVAILABILITY_URI,
      payload
    );
    const answer = response.data;
    if (answer.count === 0) {
      return 0;
    }
    const jobIds = answer.results.map((x) => x.job_id);
    jobIds.forEach((jobId) => {
      appendToRecentScans(jobId, "secondary");
    });
    addToast(
      `Found similar scan with job ID(s) #${jobIds.join(", ")}`,
      null,
      "info"
    );
    return jobIds;
  } catch (e) {
    return Promise.reject(e);
  }
}

async function _analyzeObservable(formValues) {
  const observables = [];
  formValues.observable_names.forEach((ObservableName) => {
    observables.push([formValues.classification, ObservableName]);
  });
  const body = {
    observables,
    analyzers_requested: formValues.analyzers,
    connectors_requested: formValues.connectors,
    tlp: formValues.tlp,
    runtime_configuration: formValues.runtime_configuration,
    tags_labels: formValues.tags_labels,
  };
  return axios.post(ANALYZE_MULTIPLE_OBSERVABLE_URI, body);
}

async function _analyzeFile(formValues) {
  const body = new FormData();
  Array.from(formValues.files).forEach((file) => {
    body.append("files", file, file.name);
  });
  formValues.tags_labels.map((x) => body.append("tags_labels", x));
  formValues.analyzers.map((x) => body.append("analyzers_requested", x));
  formValues.connectors.map((x) => body.append("connectors_requested", x));
  body.append("tlp", formValues.tlp);
  if (
    formValues.runtime_configuration != null &&
    Object.keys(formValues.runtime_configuration).length
  ) {
    body.append(
      "runtime_configuration",
      JSON.stringify(formValues.runtime_configuration)
    );
  }
  return axios.post(ANALYZE_MULTIPLE_FILES_URI, body);
}

async function _startPlaybookFile(formValues) {
  const playbookURI = `${API_BASE_URI}/playbook/analyze_multiple_files`;
  const body = new FormData();
  Array.from(formValues.files).forEach((file) => {
    body.append("files", file, file.name);
  });
  formValues.tags.map((x) => body.append("tags_labels", x));
  formValues.playbooks.map((x) => body.append("playbooks_requested", x));
  return axios.post(playbookURI, body);
}

async function _startPlaybookObservable(formValues) {
  const observables = [];
  formValues.observable_names.forEach((ObservableName) => {
    observables.push([formValues.classification, ObservableName]);
  });

  const playbookURI = `${API_BASE_URI}/playbook/analyze_multiple_observables`;
  const body = {
    observables,
    playbooks_requested: formValues.playbooks,
    tags_labels: formValues.tags_labels,
  };

  return axios.post(playbookURI, body);
}
