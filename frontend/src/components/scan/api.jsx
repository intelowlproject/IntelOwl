/* eslint-disable no-underscore-dangle */
import React from "react";
import axios from "axios";
import md5 from "md5";

import { ContentSection, readFileAsync, addToast } from "@certego/certego-ui";

import {
  ANALYZE_OBSERVABLE_URI,
  ANALYZE_FILE_URI,
  ASK_ANALYSIS_AVAILABILITY_URI
} from "../../constants/api";
import useRecentScansStore from "../../stores/useRecentScansStore";

const { append: appendToRecentScans, } = useRecentScansStore.getState();

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

    const respData = resp.data;
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
      return Promise.resolve(jobId);
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

async function _analyzeObservable(formValues) {
  const body = {
    observable_name: formValues.observable_name,
    observable_classification: formValues.classification,
    analyzers_requested: formValues.analyzers,
    connectors_requested: formValues.connectors,
    tlp: formValues.tlp,
    runtime_configuration: formValues.runtime_configuration,
    tags_labels: formValues.tags_labels,
  };
  return axios.post(ANALYZE_OBSERVABLE_URI, body);
}

async function _analyzeFile(formValues) {
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
  return axios.post(ANALYZE_FILE_URI, body);
}