/* eslint-disable no-underscore-dangle */
import React from "react";
import axios from "axios";
import md5 from "md5";

import { ContentSection, readFileAsync, addToast } from "@certego/certego-ui";

import {
  API_BASE_URI,
  ANALYZE_OBSERVABLE_URI,
  ANALYZE_FILE_URI,
  ASK_ANALYSIS_AVAILABILITY_URI
} from "../../constants/api";
import useRecentScansStore from "../../stores/useRecentScansStore";

const { append: appendToRecentScans, } = useRecentScansStore.getState();

export async function createJob(formValues) {
  let jobIdAnalyzersAndConnectors
  let JobIdPlaybooks;
  try {
    // check existing
    if (formValues.check !== "force_new") {
      const jobId = await _askAnalysisAvailability(formValues);
      if (jobId) jobIdAnalyzersAndConnectors = Promise.resolve(jobId);
    }
    // new scan
    const [respAnalyzersAndConnectors, respPlaybooks] =
      formValues.classification === "file"
        ? await _analyzeFile(formValues)
        : await _analyzeObservable(formValues);
    
    const respArray = [respAnalyzersAndConnectors.data, respPlaybooks.data];
    console.log(respArray);
    for (let i = 0; i <= respArray.length; i += 1) {
      const respData = respArray[i];
      console.log(respData);
      // handle response/error
      if (respData.status === "accepted" || respData.status === "running") {
        const jobId = parseInt(respData.job_id, 10);
        appendToRecentScans(jobId, "success");
        addToast(
          `Created new Job with ID #${jobId}!`,
          <div>
            <ContentSection className="text-light">
              <strong>Analyzers:</strong>&nbsp;
              {respData.analyzers_running?.join(", ")}
            </ContentSection>
            {respData.connectors_running.length > 0 && (
              <ContentSection className="text-light">
                <strong>Connectors:</strong>&nbsp;    
                {respData.connectors_running.join(", ")}
              </ContentSection>

            )}
            {respData.playbooks_running.length > 0 && (
              <ContentSection className="text-light">
                <strong>Playbooks:</strong>&nbsp;
                {respData.playbooks_running.join(", ")}
              </ContentSection>
            )}
            
            {respData.warnings.length > 0 && (
              <ContentSection className="bg-accent text-darker">
                <strong>Warnings:</strong>&nbsp;{respData.warnings.join(", ")}
              </ContentSection>
            )}
          </div>,
          "success",
          true,
          10000
        );
        if (respData.playbooks_running.length !== 0) {
          JobIdPlaybooks = Promise.resolve(jobId);
        } else if (jobIdAnalyzersAndConnectors === undefined) {
          jobIdAnalyzersAndConnectors = Promise.resolve(jobId);
        }
      } else {
        addToast("Failed!", respData?.message, "danger");
        const error = new Error(`job status ${respData.status}`);
        if (respData.playbooks_running.length !== 0) {
          JobIdPlaybooks = Promise.reject(error);
        } else if (jobIdAnalyzersAndConnectors === undefined) {
          jobIdAnalyzersAndConnectors = Promise.reject(error);
        }
      }
    }
    return [jobIdAnalyzersAndConnectors, JobIdPlaybooks];

  } catch (e) {
      addToast("Failed!", e.parsedMsg, "danger");
      return [Promise.reject(e), Promise.reject(e)];
    }
}

async function _askAnalysisAvailability(formValues) {
  const body = {
    analyzers: formValues.analyzers,
    md5:
      formValues.classification === "file"
        ? md5(await readFileAsync(formValues.file))
        : md5(formValues.observable_name),
  };

  if (formValues.check === "running_only") {
    body.running_only = "True";
  }

  try {
    const response = await axios.post(ASK_ANALYSIS_AVAILABILITY_URI, body);
    const answer = response.data;
    if (answer.status === "not_available") {
      return 0;
    }

    const jobId = parseInt(answer.job_id, 10);
    appendToRecentScans(jobId, "secondary");
    addToast(`Found similar scan with job ID #${jobId}`, null, "info");
    return jobId;
    
  } catch (e) {
      return Promise.reject(e);
  }
}

async function _startPlaybook(formValues) {

  if (formValues.observable_classification === "file") {
    const playbookURI = `${API_BASE_URI}/playbook/analyze_file`;
    const body = new FormData();
    body.append("file", formValues.file, formValues.file.name);
    body.append("file_name", formValues.file.name);
    formValues.tags_labels.map((x) => body.append("tags_labels", x));
    formValues.connectors.map((x) => body.append("playbooks_requested", x));
    return axios.post(playbookURI, body);
  }
  const playbookURI = `${API_BASE_URI}/playbook/analyze_observable`;
  const body = {
    observable_name: formValues.observable_name,
    observable_classification: formValues.classification,
    playbooks_requested: formValues.playbooks,
    tags_labels: formValues.tags_labels,
  };
  return axios.post(playbookURI, body);
  }

async function _analyzeObservable(formValues) {
  let respPlaybooks;

  if (formValues.playbooks.length !== 0) {
    respPlaybooks = _startPlaybook(formValues);
  }

  const body = {
    observable_name: formValues.observable_name,
    observable_classification: formValues.classification,
    analyzers_requested: formValues.analyzers,
    connectors_requested: formValues.connectors,
    tlp: formValues.tlp,
    runtime_configuration: formValues.runtime_configuration,
    tags_labels: formValues.tags_labels,
  };

  const respAnalyzersAndConnectors = axios.post(ANALYZE_OBSERVABLE_URI, body);
  return [respAnalyzersAndConnectors, respPlaybooks];
}

async function _analyzeFile(formValues) {
  let respPlaybooks;

  if (formValues.playbooks.length !== 0) {
    respPlaybooks = _startPlaybook(formValues);
  }

  const body = new FormData();
  body.append("file", formValues.file, formValues.file.name);
  body.append("file_name", formValues.file.name);
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
  const respAnalyzersAndConnectors = axios.post(ANALYZE_FILE_URI, body);
  return [respAnalyzersAndConnectors, respPlaybooks];
}