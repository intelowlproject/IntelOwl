import axios from "axios";
import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import { JobActionsBar } from "../../../../../src/components/jobs/result/bar/JobActionBar";

import { JOB_BASE_URI } from "../../../../../src/constants/apiURLs";

jest.mock("axios");
// mock PluginConfigModal
jest.mock("../../../../../src/components/plugins/PluginConfigModal", () => ({
  PluginConfigModal: jest.fn(() => <div />),
}));

describe("test JobActionsBar", () => {
  beforeAll(() => {
    axios.post.mockImplementation(() => Promise.resolve({ data: { id: 109 } }));
  });

  const job = {
    id: 108,
    analyzable_id: 123,
    user: {
      username: "test",
    },
    tags: [],
    analyzer_reports: [
      {
        id: 174,
        name: "Classic_DNS",
        process_time: 0.07,
        report: {
          observable: "dns.google.com",
          resolutions: [
            {
              TTL: 594,
              data: "8.8.8.8",
              name: "dns.google.com",
              type: 1,
            },
            {
              TTL: 594,
              data: "8.8.4.4",
              name: "dns.google.com",
              type: 1,
            },
          ],
        },
        status: "SUCCESS",
        errors: [],
        start_time: "2023-05-31T08:19:03.380434Z",
        end_time: "2023-05-31T08:19:03.455218Z",
        runtime_configuration: {},
        type: "analyzer",
      },
    ],
    connector_reports: [],
    visualizer_reports: [],
    comments: [
      {
        id: 1,
        content: "test comment",
        created_at: "2023-05-31T09:00:14.352880Z",
        user: {
          username: "test",
        },
      },
    ],
    permissions: {
      kill: true,
      delete: true,
      plugin_actions: true,
    },
    is_sample: false,
    md5: "f9bc35a57b22f82c94dbcc420f71b903",
    observable_name: "dns.google.com",
    observable_classification: "domain",
    file_name: "",
    file_mimetype: "",
    status: "reported_without_fails",
    runtime_configuration: {
      analyzers: {},
      connectors: {},
      visualizers: {},
    },
    received_request_time: "2023-05-31T08:19:03.256003",
    finished_analysis_time: "2023-05-31T08:19:04.484684",
    process_time: 0.23,
    tlp: "AMBER",
    errors: [],
    playbook_requested: "test",
    playbook_to_execute: "test",
    analyzers_requested: ["Classic_DNS"],
    analyzers_to_execute: ["Classic_DNS"],
    connectors_requested: ["MISP", "OpenCTI", "Slack", "YETI"],
    connectors_to_execute: ["MISP", "OpenCTI", "Slack", "YETI"],
    visualizers_to_execute: [],
    investigation_id: 7,
    investigation_name: "investigation test",
  };

  test("test components", async () => {
    const { container } = render(
      <BrowserRouter>
        <JobActionsBar job={job} relatedInvestigationNumber={4} />
      </BrowserRouter>,
    );

    const investigationButton = screen.getByText("Investigation");
    expect(investigationButton).toBeInTheDocument();
    expect(investigationButton.href).toContain("/investigation/7");
    const artifactButton = screen.getByText("Artifact");
    expect(artifactButton).toBeInTheDocument();
    expect(artifactButton.href).toContain("/artifacts/123");
    expect(
      screen.getByRole("button", { name: "Comments" }),
    ).toBeInTheDocument();
    expect(screen.getByText("1")).toBeInTheDocument();

    const actionMenuButton = container.querySelector("#jobActions");
    expect(actionMenuButton).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(actionMenuButton);

    expect(screen.getByText("Related investigations:")).toBeInTheDocument();
    expect(screen.getByText("Download report")).toBeInTheDocument();
    expect(screen.getByText("Save as playbook")).toBeInTheDocument();
    expect(screen.getByText("Rescan")).toBeInTheDocument();
    expect(screen.getByText("Delete")).toBeInTheDocument();
  });

  test.each([
    // observable playbook
    {
      jobResult: job,
      type: "observable playbook",
    },
    // observable analyzer
    {
      jobResult: {
        ...job,
        playbook_requested: "",
        playbook_to_execute: "",
      },
      type: "observable analyzer",
    },
    // file playbook
    {
      jobResult: {
        ...job,
        analyzer_reports: [
          {
            id: 174,
            name: "yara",
            process_time: 0.07,
            report: {},
            status: "RUNNING",
            errors: [],
            start_time: "2023-05-31T08:19:03.380434Z",
            end_time: "2023-05-31T08:19:03.455218Z",
            runtime_configuration: {},
            type: "analyzer",
          },
        ],
        is_sample: true,
        md5: "914757470762e2177f8be4d87420254e",
        observable_name: "",
        observable_classification: "",
        file_name: "test.sh",
        file_mimetype: "text/x-shellscript",
        analyzers_requested: ["yara"],
        analyzers_to_execute: ["yara"],
        connectors_requested: [],
        connectors_to_execute: [],
      },
      type: "file playbook",
    },
    // file analyzer
    {
      jobResult: {
        ...job,
        analyzer_reports: [
          {
            id: 174,
            name: "yara",
            process_time: 0.07,
            report: {},
            status: "RUNNING",
            errors: [],
            start_time: "2023-05-31T08:19:03.380434Z",
            end_time: "2023-05-31T08:19:03.455218Z",
            runtime_configuration: {},
            type: "analyzer",
          },
        ],
        is_sample: true,
        md5: "914757470762e2177f8be4d87420254e",
        observable_name: "",
        observable_classification: "",
        file_name: "test.sh",
        file_mimetype: "text/x-shellscript",
        playbook_requested: "",
        playbook_to_execute: "",
        analyzers_requested: ["yara"],
        connectors_requested: [],
        analyzers_to_execute: ["yara"],
        connectors_to_execute: [],
      },
      type: "file analyzer",
    },
  ])("Rescan button - $type", async ({ jobResult }) => {
    render(
      <BrowserRouter>
        <JobActionsBar job={jobResult} relatedInvestigationNumber={4} />
      </BrowserRouter>,
    );

    const rescanBtn = screen.getByText("Rescan");
    expect(rescanBtn).toBeInTheDocument();

    const user = userEvent.setup();
    await user.click(rescanBtn);

    await waitFor(() => {
      expect(axios.post.mock.calls[0]).toEqual(
        // axios call
        [`${JOB_BASE_URI}/${108}/rescan`],
      );
    });
  });
});
