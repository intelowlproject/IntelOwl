/* eslint-disable no-underscore-dangle */
import React from "react";
import axios from "axios";

import { ContentSection, addToast } from "@certego/certego-ui";

import {
  ANALYZE_MULTIPLE_OBSERVABLE_URI,
  ANALYZE_MULTIPLE_FILES_URI,
  COMMENT_BASE_URI,
  PLAYBOOKS_ANALYZE_MULTIPLE_FILES_URI,
  PLAYBOOKS_ANALYZE_MULTIPLE_OBSERVABLE_URI,
} from "../../constants/api";
import { scanMode } from "../../constants/constants";

function prettifyErrors(errorResponse) {
  // only validation errors returns an array of errors
  /**
    "errors":{
			"detail":[
				{"observable_name":["This field may not be blank.", "another error"]},
				{"another_key": "another error"},
			]
		}
   */
  if (Array.isArray(errorResponse.response.data?.errors?.detail)) {
    let prettyHTMLList = [];
    errorResponse.response.data.errors.detail.forEach((objectDict) => {
      Object.values(objectDict).forEach((errorItem) => {
        if (Array.isArray(errorItem)) {
          errorItem.forEach((error) => prettyHTMLList.push(error));
        } else {
          prettyHTMLList.push(errorItem);
        }
      });
    });
    prettyHTMLList = prettyHTMLList.map((e) => <li>{e}</li>);
    return <ul>{prettyHTMLList}</ul>;
  }

  return JSON.stringify(errorResponse.response.data);
}

function toastBody(respData, warnings) {
  return (
    <div>
      <ContentSection className="text-light">
        <strong>Playbooks:</strong>&nbsp;
        {respData[0].playbook_running}
      </ContentSection>
      {warnings.length > 0 && (
        <ContentSection className="bg-accent text-darker">
          <strong>Warnings:</strong>&nbsp;{warnings.join(", ")}
        </ContentSection>
      )}
    </div>
  );
}

export async function createPlaybookJob(formValues) {
  try {
    // new scan
    const resp =
      formValues.classification === "file"
        ? await _startPlaybookFile(formValues)
        : await _startPlaybookObservable(formValues);

    const warnings = [];
    const respData = resp.data.results;

    respData.forEach((x) => {
      if (x.warnings) warnings.push(...x.warnings);
    });

    // handle response/error
    if (
      respData.every(
        (element) =>
          element.status === "accepted" || element.status === "exists",
      )
    ) {
      const jobIdsAccepted = [];
      const jobIdsExists = [];
      respData.forEach((x) => {
        if (x.status === "accepted")
          jobIdsAccepted.push(parseInt(x.job_id, 10));
        if (x.status === "exists") jobIdsExists.push(parseInt(x.job_id, 10));
      });
      // toast for accepted jobs
      if (jobIdsAccepted.length > 0) {
        addToast(
          `Created new Job with ID(s) #${jobIdsAccepted.join(", ")}!`,
          toastBody(respData, warnings),
          "success",
          true,
          10000,
        );
      }
      // toast for existing jobs
      if (jobIdsExists.length > 0) {
        addToast(
          `Reported existing Job with ID(s) #${jobIdsExists.join(", ")}!`,
          toastBody(respData, warnings),
          "info",
          true,
          10000,
        );
      }
      return Promise.resolve(jobIdsAccepted.concat(jobIdsExists));
    }
    // else
    addToast("Failed!", respData?.message, "danger");
    const error = new Error(`job status ${respData.status}`);
    return Promise.reject(error);
  } catch (e) {
    console.error(e);
    addToast("Failed!", prettifyErrors(e), "danger");
    return Promise.reject(e);
  }
}

export async function createComment(formValues) {
  try {
    const resp = await axios.post(`${COMMENT_BASE_URI}`, formValues);

    return Promise.resolve(resp);
  } catch (e) {
    console.error(e);
    addToast("Failed!", prettifyErrors(e), "danger");
    return Promise.reject(e);
  }
}

export async function deleteComment(commentId) {
  try {
    const resp = await axios.delete(`${COMMENT_BASE_URI}/${commentId}`);

    return Promise.resolve(resp);
  } catch (e) {
    console.error(e);
    addToast("Failed!", prettifyErrors(e), "danger");
    return Promise.reject(e);
  }
}

export async function createJob(formValues) {
  try {
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
          analyzersRunning.add(analyzer),
        );
      if (x.connectors_running)
        x.connectors_running.forEach((connector) =>
          connectorsRunning.add(connector),
        );
      if (x.warnings) warnings.push(...x.warnings);
    });
    // handle response/error
    if (
      respData.every(
        (element) =>
          element.status === "accepted" || element.status === "exists",
      )
    ) {
      const jobIds = respData.map((x) => parseInt(x.job_id, 10));
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
        10000,
      );
      return Promise.resolve(jobIds);
    }

    // else
    addToast("Failed!", respData?.message, "danger");
    const error = new Error(`job status ${respData.status}`);
    return Promise.reject(error);
  } catch (e) {
    console.error(e);
    addToast("Failed!", prettifyErrors(e), "danger");
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
    tlp: formValues.tlp,
    scan_mode: parseInt(formValues.scan_mode, 10),
  };
  // analyzers
  if (formValues.analyzers.length) {
    body.analyzers_requested = formValues.analyzers;
  }
  // connectors
  if (formValues.connectors.length) {
    body.connectors_requested = formValues.connectors;
  }
  // tags
  if (formValues.tags_labels.length) {
    body.tags_labels = formValues.tags_labels;
  }
  // runtime configuration
  if (
    formValues.runtime_configuration != null &&
    Object.keys(formValues.runtime_configuration).length
  ) {
    body.runtime_configuration = formValues.runtime_configuration;
  }
  // scan mode
  if (formValues.scan_mode === scanMode.CHECK_PREVIOUS_ANALYSIS) {
    body.scan_check_time = `${formValues.scan_check_time}:00:00`;
  }
  return axios.post(ANALYZE_MULTIPLE_OBSERVABLE_URI, body);
}

async function _analyzeFile(formValues) {
  const body = new FormData();
  // file
  Array.from(formValues.files).forEach((file) => {
    body.append("files", file, file.name);
  });
  // tags
  if (formValues.tags_labels.length) {
    formValues.tags_labels.forEach((tag) => body.append("tags_labels", tag));
  }
  // analyzers
  if (formValues.analyzers.length) {
    formValues.analyzers.forEach((analyzer) =>
      body.append("analyzers_requested", analyzer),
    );
  }
  // connectors
  if (formValues.connectors.length) {
    formValues.connectors.forEach((connector) =>
      body.append("connectors_requested", connector),
    );
  }
  // tlp
  body.append("tlp", formValues.tlp);
  // runtime configuration
  if (
    formValues.runtime_configuration != null &&
    Object.keys(formValues.runtime_configuration).length
  ) {
    body.append(
      "runtime_configuration",
      JSON.stringify(formValues.runtime_configuration),
    );
  }
  // scan mode
  body.append("scan_mode", formValues.scan_mode);
  // scan check time
  if (formValues.scan_mode === scanMode.CHECK_PREVIOUS_ANALYSIS) {
    body.append("scan_check_time", `${formValues.scan_check_time}:00:00`);
  }
  console.debug("_analyzeFile", body);
  return axios.post(ANALYZE_MULTIPLE_FILES_URI, body);
}

async function _startPlaybookFile(formValues) {
  const body = new FormData();
  // file
  Array.from(formValues.files).forEach((file) => {
    body.append("files", file, file.name);
  });
  // tlp
  body.append("tlp", formValues.tlp);
  // tags
  if (formValues.tags_labels.length) {
    formValues.tags_labels.forEach((tag) => body.append("tags_labels", tag));
  }
  // playbook requested
  body.append("playbook_requested", formValues.playbook);
  // scan mode
  body.append("scan_mode", formValues.scan_mode);
  // scan check time
  if (formValues.scan_mode === scanMode.CHECK_PREVIOUS_ANALYSIS) {
    body.append("scan_check_time", `${formValues.scan_check_time}:00:00`);
  }
  console.debug("_analyzeFile", body);
  return axios.post(PLAYBOOKS_ANALYZE_MULTIPLE_FILES_URI, body);
}

async function _startPlaybookObservable(formValues) {
  const observables = [];
  formValues.observable_names.forEach((ObservableName) => {
    observables.push([formValues.classification, ObservableName]);
  });

  const body = {
    observables,
    playbook_requested: formValues.playbook,
    tlp: formValues.tlp,
    scan_mode: parseInt(formValues.scan_mode, 10),
  };
  if (formValues.tags_labels.length) {
    body.tags_labels = formValues.tags_labels;
  }
  if (formValues.scan_mode === scanMode.CHECK_PREVIOUS_ANALYSIS) {
    body.scan_check_time = `${formValues.scan_check_time}:00:00`;
  }
  console.debug("_analyzeObservable", body);
  return axios.post(PLAYBOOKS_ANALYZE_MULTIPLE_OBSERVABLE_URI, body);
}
