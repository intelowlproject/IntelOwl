import React from "react";
import { addToast } from "@certego/certego-ui";
import axios from "axios";

import { PLAYBOOKS_CONFIG_URI } from "../../../../constants/apiURLs";

export async function saveJobAsPlaybook(values) {
  let success = false;
  const data = {
    name: values.name,
    description: values.description,
    analyzers: values.analyzers,
    connectors: values.connectors,
    pivots: values.pivots,
    runtime_configuration: values.runtimeConfiguration,
    tags_labels: values.tags_labels,
    tlp: values.tlp,
    scan_mode: values.scan_mode,
    scan_check_time: values.scan_check_time,
  };
  try {
    const response = await axios.post(PLAYBOOKS_CONFIG_URI, data);

    success = response.status === 200;
    if (success) {
      addToast(
        <span>
          Playbook with name {response.data.name} created with success
        </span>,
        null,
        "info",
      );
    }
  } catch (error) {
    addToast(
      <span>Failed creation of playbook with name {values.name}</span>,
      error.parsedMsg,
      "warning",
    );
  }
  return success;
}
