import React from "react";
import axios from "axios";

import { ContentSection, addToast } from "@certego/certego-ui";

import {
  ANALYZE_MULTIPLE_OBSERVABLE_URI,
  ANALYZE_MULTIPLE_FILES_URI,
  PLAYBOOKS_ANALYZE_MULTIPLE_FILES_URI,
  PLAYBOOKS_ANALYZE_MULTIPLE_OBSERVABLE_URI,
} from "../../constants/apiURLs";
import { prettifyErrors } from "../../utils/api";

import { ScanModesNumeric } from "../../constants/advancedSettingsConst";
import { JobTypes } from "../../constants/jobConst";
import { getObservableClassification } from "../../utils/observables";

function sampleArrayPayload(data, fieldName, payload) {
  Array.from(data).forEach((value) => {
    payload.append(fieldName, value);
  });
}

function createJobPayload(
  analyzables,
  isSample,
  playbook,
  analyzers,
  connectors,
  runtimeConfig,
  tags,
  tlp,
  _scanMode,
  scanCheckTime,
  investigationIdParam,
  parentIdParam,
) {
  let payload = {};
  /* we add a custom function to the object to reuse the code:
  in this way append method is available for bot FormData and {}.
  Remember to delete this before send the request to the backend!
  */
  // eslint-disable-next-line no-return-assign
  payload.append = (key, value) => (payload[key] = value);
  if (isSample) {
    payload = new FormData();
  }
  // populate payload
  // file
  if (isSample) {
    Array.from(analyzables).forEach((file) => {
      payload.append("files", file, file.name);
    });
  } else {
    const observables = [];
    analyzables.forEach((observable) => {
      observables.push([getObservableClassification(observable), observable]);
    });
    payload.append("observables", observables);
  }
  // playbook
  if (playbook) {
    payload.append("playbook_requested", playbook);
  } else {
    // analyzers
    if (analyzers.length) {
      if (isSample)
        sampleArrayPayload(analyzers, "analyzers_requested", payload);
      else payload.append("analyzers_requested", analyzers);
    }
    // connectors
    if (connectors.length) {
      if (isSample)
        sampleArrayPayload(connectors, "connectors_requested", payload);
      else payload.append("connectors_requested", connectors);
    }
  }
  // runtime configuration
  if (runtimeConfig != null && Object.keys(runtimeConfig).length) {
    const runtimeConfigTosend = runtimeConfig;
    /* visualized is required from the backend so we need to send it.
      Also it's useless to edit it, so it's not present in the UI and added only in the request.
    */
    if (!Object.keys(runtimeConfigTosend).includes("visualizers"))
      runtimeConfigTosend.visualizers = {};
    payload.append(
      "runtime_configuration",
      isSample ? JSON.stringify(runtimeConfigTosend) : runtimeConfigTosend,
    );
  }

  // advanced configs
  // tags
  if (tags.length) {
    if (isSample) sampleArrayPayload(tags, "tags_labels", payload);
    else payload.append("tags_labels", tags);
  }
  // tlp
  payload.append("tlp", tlp);
  // scan mode and scan time
  payload.append("scan_mode", parseInt(_scanMode, 10));
  if (_scanMode === ScanModesNumeric.CHECK_PREVIOUS_ANALYSIS) {
    payload.append("scan_check_time", `${scanCheckTime}:00:00`);
  }
  // investigation id in param
  if (investigationIdParam) {
    payload.append("investigation", investigationIdParam);
  }
  // parent id in param
  if (parentIdParam) {
    payload.append("parent_job", parentIdParam);
  }
  // remove custom method in order to avoid to send it to the backend
  if (!isSample) delete payload.append;
  console.debug("job request params:");
  console.debug(payload);
  return payload;
}

function playbookToastBody(respData, warnings) {
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

function customToastBody(analyzersRunning, connectorsRunning, warnings) {
  return (
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
    </div>
  );
}

export async function createJob(
  analyzables,
  classification,
  playbook,
  analyzers,
  connectors,
  runtimeConfig,
  tags,
  tlp,
  _scanMode,
  scanCheckTime,
  investigationIdParam,
  parentIdParam,
) {
  try {
    console.debug(
      `create job with: analyzables: ${analyzables}, classification: ${classification}, playbook: ${playbook},
      analyzers: ${analyzers}, connectors: ${connectors}, runtimeConfig: ${JSON.stringify(
        runtimeConfig,
      )}, 
      tags: ${tags}, tlp: ${tlp}, ScanModesNumeric: ${_scanMode}, scanCheckTime: ${scanCheckTime}`,
    );
    const isSample = classification === JobTypes.FILE;
    let analyzablesToSubmit = analyzables;
    let apiUrl = "";
    if (isSample) {
      if (playbook) {
        apiUrl = PLAYBOOKS_ANALYZE_MULTIPLE_FILES_URI;
      } else {
        apiUrl = ANALYZE_MULTIPLE_FILES_URI;
      }
    } else {
      // eliminate duplicates (only for obs, it seems to have no effect for files)
      analyzablesToSubmit = [...new Set(analyzables)];
      if (playbook) {
        apiUrl = PLAYBOOKS_ANALYZE_MULTIPLE_OBSERVABLE_URI;
      } else {
        apiUrl = ANALYZE_MULTIPLE_OBSERVABLE_URI;
      }
    }

    const payload = createJobPayload(
      analyzablesToSubmit,
      isSample,
      playbook,
      analyzers,
      connectors,
      runtimeConfig,
      tags,
      tlp,
      _scanMode,
      scanCheckTime,
      investigationIdParam,
      parentIdParam,
    );
    const resp = await axios.post(apiUrl, payload, {
      headers: {
        "Content-Type": isSample ? "multipart/form-data" : "application/json",
      },
    });
    const respData = resp.data.results;

    const warnings = [];
    respData.forEach((job) => {
      if (job.warnings) warnings.push(...job.warnings);
    });

    let toastBody;
    if (playbook) {
      toastBody = playbookToastBody(respData, warnings);
    } else {
      const analyzersRunning = [];
      const connectorsRunning = [];
      respData.forEach((job) => {
        analyzersRunning.push(...job.analyzers_running);
        connectorsRunning.push(...job.connectors_running);
      });
      toastBody = customToastBody(
        new Set(analyzersRunning),
        new Set(connectorsRunning),
        warnings,
      );
    }

    // handle response/error
    if (respData.every((element) => element.status === "accepted")) {
      const jobIdsAccepted = [];
      const jobIdsExists = [];
      respData.forEach((job) => {
        if (job.already_exists) {
          jobIdsExists.push(parseInt(job.job_id, 10));
        } else {
          jobIdsAccepted.push(parseInt(job.job_id, 10));
        }
      });
      if (jobIdsAccepted.length > 0) {
        addToast(
          `Created new Job with ID(s) #${jobIdsAccepted.join(", ")}!`,
          toastBody,
          "success",
          true,
          10000,
        );
      }
      // toast for existing jobs
      if (jobIdsExists.length > 0) {
        addToast(
          `Reported existing Job with ID(s) #${jobIdsExists.join(", ")}!`,
          toastBody,
          "info",
          true,
          10000,
        );
      }
      return Promise.resolve({
        jobIds: jobIdsAccepted.concat(jobIdsExists),
        investigationId: parseInt(respData[0].investigation, 10) || null,
      });
    }
    // else
    addToast("Failed!", respData?.message, "danger");
    const error = new Error(`job status ${respData.status}`);
    return Promise.reject(error);
  } catch (error) {
    console.error(error);
    addToast("Failed!", prettifyErrors(error), "danger");
    return Promise.reject(error);
  }
}
