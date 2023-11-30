import axios from "axios";
import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import { JobActionsBar } from "../../../../../src/components/jobs/result/bar/JobActionBar";

import {
  ANALYZE_MULTIPLE_OBSERVABLE_URI,
  PLAYBOOKS_ANALYZE_MULTIPLE_OBSERVABLE_URI,
} from "../../../../../src/constants/apiURLs";

jest.mock("axios");
describe("test JobActionsBar", () => {
  beforeAll(() => {
    axios.post.mockImplementation(() =>
      Promise.resolve({ data: { results: [], count: 0 } }),
    );
  });

  test("rescan observable playbook", async () => {
    axios.post.mockImplementation(() =>
      Promise.resolve({
        data: {
          results: [
            {
              job_id: 108,
              analyzers_running: ["Classic_DNS"],
              connectors_running: [],
              visualizers_running: [],
              playbook_running: "test",
              status: "accepted",
              already_exists: true,
            },
          ],
          count: 0,
        },
      }),
    );

    render(
      <BrowserRouter>
        <JobActionsBar
          job={{
            id: 108,
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
            connectors_requested: [],
            connectors_to_execute: [],
            visualizers_to_execute: [],
          }}
        />
      </BrowserRouter>,
    );

    const scanBtn = screen.getByText("Rescan");
    expect(scanBtn).toBeInTheDocument();

    const user = userEvent.setup();
    await user.click(scanBtn);

    await waitFor(() => {
      expect(axios.post.mock.calls[0]).toEqual(
        // axios call
        [
          PLAYBOOKS_ANALYZE_MULTIPLE_OBSERVABLE_URI,
          {
            observables: [["domain", "dns.google.com"]],
            playbook_requested: "test",
            tlp: "AMBER",
            scan_mode: 1,
            runtime_configuration: {
              analyzers: {},
              connectors: {},
              visualizers: {},
            },
          },
          { headers: { "Content-Type": "application/json" } },
        ],
      );
    });
  });

  test("rescan observable analyzer", async () => {
    render(
      <BrowserRouter>
        <JobActionsBar
          job={{
            id: 108,
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
            playbook_requested: "",
            playbook_to_execute: "",
            analyzers_requested: ["Classic_DNS"],
            connectors_requested: ["MISP", "OpenCTI", "Slack", "YETI"],
            analyzers_to_execute: ["Classic_DNS"],
            connectors_to_execute: [],
            visualizers_to_execute: [],
          }}
        />
      </BrowserRouter>,
    );

    const scanBtn = screen.getByText("Rescan");
    expect(scanBtn).toBeInTheDocument();

    const user = userEvent.setup();
    await user.click(scanBtn);

    await waitFor(() => {
      expect(axios.post.mock.calls[0]).toEqual(
        // axios call
        [
          ANALYZE_MULTIPLE_OBSERVABLE_URI,
          {
            observables: [["domain", "dns.google.com"]],
            analyzers_requested: ["Classic_DNS"],
            connectors_requested: ["MISP", "OpenCTI", "Slack", "YETI"],
            runtime_configuration: {
              analyzers: {},
              connectors: {},
              visualizers: {},
            },
            tlp: "AMBER",
            scan_mode: 1,
          },
          { headers: { "Content-Type": "application/json" } },
        ],
      );
    });
  });

  test("rescan file playbook", async () => {
    axios.post.mockImplementation(() =>
      Promise.resolve({
        data: {
          results: [
            {
              job_id: 108,
              analyzers_running: [],
              connectors_running: [],
              visualizers_running: [],
              playbook_running: "test",
              status: "accepted",
              already_exists: true,
            },
          ],
          count: 0,
        },
      }),
    );

    render(
      <BrowserRouter>
        <JobActionsBar
          job={{
            id: 108,
            user: {
              username: "test",
            },
            tags: [],
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
            is_sample: true,
            md5: "914757470762e2177f8be4d87420254e",
            observable_name: "",
            observable_classification: "",
            file_name: "test.sh",
            file_mimetype: "text/x-shellscript",
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
            analyzers_requested: ["yara"],
            analyzers_to_execute: ["yara"],
            connectors_requested: [],
            connectors_to_execute: [],
            visualizers_to_execute: [],
          }}
        />
      </BrowserRouter>,
    );

    const scanBtn = screen.getByText("Rescan");
    expect(scanBtn).toBeInTheDocument();

    const user = userEvent.setup();
    await user.click(scanBtn);

    await waitFor(() => {
      expect(axios.post.mock.calls[0]).toEqual(
        // axios call
        undefined,
      );
    });
    setTimeout(() => {
      expect(
        screen.getByText("It's not possible to repeat a sample analysis"),
      ).toBeInTheDocument();
    }, 15 * 1000);
  });

  test("rescan file analyzer", async () => {
    render(
      <BrowserRouter>
        <JobActionsBar
          job={{
            id: 108,
            user: {
              username: "test",
            },
            tags: [],
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
            is_sample: true,
            md5: "914757470762e2177f8be4d87420254e",
            observable_name: "",
            observable_classification: "",
            file_name: "test.sh",
            file_mimetype: "text/x-shellscript",
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
            playbook_requested: "",
            playbook_to_execute: "",
            analyzers_requested: ["yara"],
            connectors_requested: [],
            analyzers_to_execute: ["yara"],
            connectors_to_execute: [],
            visualizers_to_execute: [],
          }}
        />
      </BrowserRouter>,
    );

    const scanBtn = screen.getByText("Rescan");
    expect(scanBtn).toBeInTheDocument();

    const user = userEvent.setup();
    await user.click(scanBtn);

    await waitFor(() => {
      expect(axios.post.mock.calls[0]).toEqual(
        // axios call
        undefined,
      );
    });
    setTimeout(() => {
      expect(
        screen.getByText("It's not possible to repeat a sample analysis"),
      ).toBeInTheDocument();
    }, 15 * 1000);
  });
});
