import React from "react";
import "@testing-library/jest-dom";
import { render, screen, within } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import { JobOverview } from "../../../../../src/components/jobs/result/utils";

describe("test JobOverview (job report)", () => {
  test("no visualizer", async () => {
    const { container } = render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          refetch={() => {}}
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
            playbook_requested: null,
            playbook_to_execute: null,
            analyzers_requested: ["Classic_DNS"],
            connectors_requested: ["MISP", "OpenCTI", "Slack", "YETI"],
            analyzers_to_execute: ["Classic_DNS"],
            connectors_to_execute: [],
            visualizers_to_execute: [],
          }}
        />
      </BrowserRouter>
    );

    // utility bar
    const utilitiesRow = container.querySelector("#utilitiesRow");
    expect(within(utilitiesRow).getByText("Job #108")).toBeInTheDocument();
    const goBackButton = within(utilitiesRow).getByRole("button", { name: "" });
    expect(goBackButton.id).toBe("gobackbutton");
    expect(
      within(utilitiesRow).getByRole("button", { name: "Comments (1)" })
    ).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Delete Job" })
    ).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Rescan" })
    ).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Save As Playbook" })
    ).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Raw JSON" })
    ).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Share" })
    ).toBeInTheDocument();
    // metadata - first line
    const JobInfoCardSection = container.querySelector("#JobInfoCardSection");
    expect(
      within(JobInfoCardSection).getByText("dns.google.com")
    ).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("Status")).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("REPORTED WITHOUT FAILS")
    ).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("TLP")).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("AMBER")).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("User")).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("test")).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("MD5")).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("f9bc35a57b22f82c94dbcc420f71b903")
    ).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("Process Time (mm:ss)")
    ).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("00:00")).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("Start Time")
    ).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("08:19:03 AM May 31st, 2023")
    ).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("End Time")
    ).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("08:19:04 AM May 31st, 2023")
    ).toBeInTheDocument();
    // metadata - second line
    expect(within(JobInfoCardSection).getByText("Tags")).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("Error(s)")
    ).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("Playbook")
    ).toBeInTheDocument();
    // visualizable selector (check RAW is selected)
    const visualizerButton = screen.getByRole("button", { name: "Visualizer" });
    expect(visualizerButton).toBeInTheDocument();
    expect(visualizerButton.className).toContain("btn-outline-tertiary"); // not selected
    const rawButton = screen.getByRole("button", { name: "Raw" });
    expect(rawButton).toBeInTheDocument();
    expect(rawButton.className).toContain("btn-primary"); // selected
    // raw data section available and analyzer is selected (it's the first)
    const analyzerReport = screen.getByText("Analyzers Report");
    expect(analyzerReport).toBeInTheDocument();
    expect(analyzerReport.closest("a").className).toContain("active");
    expect(screen.getByText("Connectors Report")).toBeInTheDocument();
    expect(screen.getByText("Visualizers Report")).toBeInTheDocument();

    // in case the visualizers are not available and the use goes to the visualizer section shows a message
    const user = userEvent.setup();
    await user.click(visualizerButton);
    expect(screen.getByText("No visualizers available.")).toBeInTheDocument();
  });

  test("visualizer error", () => {
    const { container } = render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          refetch={() => {}}
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
            visualizer_reports: [
              {
                id: 104,
                name: "test visualizer",
                process_time: 0.03,
                report: [],
                status: "FAILED",
                errors: ["test error"],
                start_time: "2023-05-30T13:45:04.942529Z",
                end_time: "2023-05-30T13:45:04.972004Z",
                runtime_configuration: {},
                type: "visualizer",
              },
            ],
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
            playbook_requested: null,
            playbook_to_execute: null,
            analyzers_requested: ["Classic_DNS"],
            connectors_requested: ["MISP", "OpenCTI", "Slack", "YETI"],
            analyzers_to_execute: ["Classic_DNS"],
            connectors_to_execute: [],
            visualizers_to_execute: [],
          }}
        />
      </BrowserRouter>
    );

    // utility bar
    const utilitiesRow = container.querySelector("#utilitiesRow");
    expect(within(utilitiesRow).getByText("Job #108")).toBeInTheDocument();
    const goBackButton = within(utilitiesRow).getByRole("button", { name: "" });
    expect(goBackButton.id).toBe("gobackbutton");
    expect(
      within(utilitiesRow).getByRole("button", { name: "Comments (1)" })
    ).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Delete Job" })
    ).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Rescan" })
    ).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Save As Playbook" })
    ).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Raw JSON" })
    ).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Share" })
    ).toBeInTheDocument();
    // metadata - first line
    const JobInfoCardSection = container.querySelector("#JobInfoCardSection");
    expect(
      within(JobInfoCardSection).getByText("dns.google.com")
    ).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("Status")).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("REPORTED WITHOUT FAILS")
    ).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("TLP")).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("AMBER")).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("User")).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("test")).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("MD5")).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("f9bc35a57b22f82c94dbcc420f71b903")
    ).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("Process Time (mm:ss)")
    ).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("00:00")).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("Start Time")
    ).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("08:19:03 AM May 31st, 2023")
    ).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("End Time")
    ).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("08:19:04 AM May 31st, 2023")
    ).toBeInTheDocument();
    // metadata - second line
    expect(within(JobInfoCardSection).getByText("Tags")).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("Error(s)")
    ).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("Playbook")
    ).toBeInTheDocument();
    // visualizable selector (check Visualizers is selected)
    const visualizerButton = screen.getByRole("button", { name: "Visualizer" });
    expect(visualizerButton).toBeInTheDocument();
    expect(visualizerButton.className).toContain("btn-primary"); // selected
    const rawButton = screen.getByRole("button", { name: "Raw" });
    expect(rawButton).toBeInTheDocument();
    expect(rawButton.className).toContain("btn-outline-tertiary"); // not selected
    // the visualizer is selected in the navbar
    const visualizer = screen.getByText("test visualizer");
    expect(visualizer.closest("a").className).toContain("active");
    expect(screen.getByText("test error")).toBeInTheDocument();
    // raw data section not rendered
    expect(screen.queryByText("Analyzers Report")).toBeNull();
    expect(screen.queryByText("Connectors Report")).toBeNull();
    expect(screen.queryByText("Visualizers Report")).toBeNull();
  });

  test("visualizer reported successfully", () => {
    const { container } = render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          refetch={() => {}}
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
            visualizer_reports: [
              {
                id: 105,
                name: "test visualizer",
                process_time: 0.04,
                report: [
                  {
                    level: 1,
                    elements: {
                      type: "horizontal_list",
                      values: [
                        {
                          name: {
                            bold: false,
                            icon: "",
                            link: "",
                            size: "auto",
                            type: "base",
                            color: "",
                            value: "Classic DNS (2)",
                            italic: false,
                            disable: false,
                            alignment: "center",
                          },
                          open: true,
                          size: "auto",
                          type: "vertical_list",
                          values: [
                            {
                              bold: false,
                              icon: "",
                              link: "",
                              size: "auto",
                              type: "base",
                              color: "",
                              value: "8.8.8.8",
                              italic: false,
                              disable: false,
                              alignment: "center",
                            },
                            {
                              bold: false,
                              icon: "",
                              link: "",
                              size: "auto",
                              type: "base",
                              color: "",
                              value: "8.8.4.4",
                              italic: false,
                              disable: false,
                              alignment: "center",
                            },
                          ],
                          disable: false,
                          alignment: "center",
                        },
                      ],
                      alignment: "around",
                    },
                  },
                ],
                status: "SUCCESS",
                errors: [],
                start_time: "2023-05-30T14:03:21.873898Z",
                end_time: "2023-05-30T14:03:21.915887Z",
                runtime_configuration: {},
                type: "visualizer",
              },
            ],
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
            playbook_requested: null,
            playbook_to_execute: null,
            analyzers_requested: ["Classic_DNS"],
            connectors_requested: ["MISP", "OpenCTI", "Slack", "YETI"],
            analyzers_to_execute: ["Classic_DNS"],
            connectors_to_execute: [],
            visualizers_to_execute: [],
          }}
        />
      </BrowserRouter>
    );

    // utility bar
    const utilitiesRow = container.querySelector("#utilitiesRow");
    expect(within(utilitiesRow).getByText("Job #108")).toBeInTheDocument();
    const goBackButton = within(utilitiesRow).getByRole("button", { name: "" });
    expect(goBackButton.id).toBe("gobackbutton");
    expect(
      within(utilitiesRow).getByRole("button", { name: "Comments (1)" })
    ).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Delete Job" })
    ).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Rescan" })
    ).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Save As Playbook" })
    ).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Raw JSON" })
    ).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Share" })
    ).toBeInTheDocument();
    // metadata - first line
    const JobInfoCardSection = container.querySelector("#JobInfoCardSection");
    expect(
      within(JobInfoCardSection).getByText("dns.google.com")
    ).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("Status")).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("REPORTED WITHOUT FAILS")
    ).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("TLP")).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("AMBER")).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("User")).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("test")).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("MD5")).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("f9bc35a57b22f82c94dbcc420f71b903")
    ).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("Process Time (mm:ss)")
    ).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("00:00")).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("Start Time")
    ).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("08:19:03 AM May 31st, 2023")
    ).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("End Time")
    ).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("08:19:04 AM May 31st, 2023")
    ).toBeInTheDocument();
    // metadata - second line
    expect(within(JobInfoCardSection).getByText("Tags")).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("Error(s)")
    ).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("Playbook")
    ).toBeInTheDocument();
    // visualizable selector (check Visualizers is selected)
    const visualizerButton = screen.getByRole("button", { name: "Visualizer" });
    expect(visualizerButton).toBeInTheDocument();
    expect(visualizerButton.className).toContain("btn-primary"); // selected
    const rawButton = screen.getByRole("button", { name: "Raw" });
    expect(rawButton).toBeInTheDocument();
    expect(rawButton.className).toContain("btn-outline-tertiary"); // not selected
    // the visualizer is selected in the navbar
    const visualizer = screen.getByText("test visualizer");
    expect(visualizer.closest("a").className).toContain("active");
    expect(screen.getByText("Classic DNS (2)")).toBeInTheDocument();
    // raw data section not rendered
    expect(screen.queryByText("Analyzers Report")).toBeNull();
    expect(screen.queryByText("Connectors Report")).toBeNull();
    expect(screen.queryByText("Visualizers Report")).toBeNull();
  });

  test("visualizer running", () => {
    const { container } = render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          refetch={() => {}}
          job={{
            id: 108,
            user: {
              username: "test",
            },
            tags: [],
            analyzer_reports: [
              {
                id: 225,
                name: "Classic_DNS",
                process_time: 0,
                report: {},
                status: "RUNNING",
                errors: [],
                start_time: "2023-05-31T12:40:15.684476Z",
                end_time: "2023-05-31T12:40:15.684492Z",
                runtime_configuration: {},
                type: "analyzer",
              },
            ],
            connector_reports: [],
            visualizer_reports: [],
            comments: [],
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
            status: "running",
            runtime_configuration: {
              analyzers: {},
              connectors: {},
              visualizers: {},
            },
            received_request_time: "2023-05-31T08:19:03.256003",
            finished_analysis_time: null,
            process_time: null,
            tlp: "AMBER",
            errors: [],
            playbook_requested: "test_dns",
            playbook_to_execute: "test_dns",
            analyzers_requested: ["Classic_DNS"],
            connectors_requested: ["MISP", "OpenCTI", "Slack", "YETI"],
            analyzers_to_execute: ["Classic_DNS"],
            connectors_to_execute: [],
            visualizers_to_execute: ["test visualizer"],
          }}
        />
      </BrowserRouter>
    );

    // utility bar
    const utilitiesRow = container.querySelector("#utilitiesRow");
    expect(within(utilitiesRow).getByText("Job #108")).toBeInTheDocument();
    const goBackButton = within(utilitiesRow).getByRole("button", { name: "" });
    expect(goBackButton.id).toBe("gobackbutton");
    expect(
      within(utilitiesRow).getByRole("button", { name: "Comments (0)" })
    ).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Delete Job" })
    ).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Rescan" })
    ).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Save As Playbook" })
    ).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Raw JSON" })
    ).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Share" })
    ).toBeInTheDocument();
    // metadata - first line
    const JobInfoCardSection = container.querySelector("#JobInfoCardSection");
    expect(
      within(JobInfoCardSection).getByText("dns.google.com")
    ).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("Status")).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("RUNNING")).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("TLP")).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("AMBER")).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("User")).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("test")).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("MD5")).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("f9bc35a57b22f82c94dbcc420f71b903")
    ).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("Process Time (mm:ss)")
    ).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("00:00")).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("Start Time")
    ).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("08:19:03 AM May 31st, 2023")
    ).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("End Time")
    ).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("-")).toBeInTheDocument();
    // metadata - second line
    expect(within(JobInfoCardSection).getByText("Tags")).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("Error(s)")
    ).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("Playbook")
    ).toBeInTheDocument();
    // visualizable selector (check Visualizers is selected)
    const visualizerButton = screen.getByRole("button", { name: "Visualizer" });
    expect(visualizerButton).toBeInTheDocument();
    expect(visualizerButton.className).toContain("btn-primary"); // selected
    const rawButton = screen.getByRole("button", { name: "Raw" });
    expect(rawButton).toBeInTheDocument();
    expect(rawButton.className).toContain("btn-outline-tertiary"); // not selected
    // LOADING SPINNER
    expect(
      container.querySelector("#visualizerLoadingSpinner")
    ).toBeInTheDocument();
    // raw data section not rendered
    expect(screen.queryByText("Analyzers Report")).toBeNull();
    expect(screen.queryByText("Connectors Report")).toBeNull();
    expect(screen.queryByText("Visualizers Report")).toBeNull();
  });

  test("user interaction with visualizer section", async () => {
    /* this test checks:
        1 - in case user goes to raw from visualizer and come back to visualizer show again the first visualizer
        2 - in case the user change visualizer shows the other visualizer UI
        3 - in case the user change raw section shows the other raw sections
        */
    const user = userEvent.setup();

    const { container } = render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          refetch={() => {}}
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
            visualizer_reports: [
              {
                id: 105,
                name: "test visualizer",
                process_time: 0.04,
                report: [
                  {
                    level: 1,
                    elements: {
                      type: "horizontal_list",
                      values: [
                        {
                          name: {
                            bold: false,
                            icon: "",
                            link: "",
                            size: "auto",
                            type: "base",
                            color: "",
                            value: "Classic DNS (2)",
                            italic: false,
                            disable: false,
                            alignment: "center",
                          },
                          open: true,
                          size: "auto",
                          type: "vertical_list",
                          values: [
                            {
                              bold: false,
                              icon: "",
                              link: "",
                              size: "auto",
                              type: "base",
                              color: "",
                              value: "8.8.8.8",
                              italic: false,
                              disable: false,
                              alignment: "center",
                            },
                            {
                              bold: false,
                              icon: "",
                              link: "",
                              size: "auto",
                              type: "base",
                              color: "",
                              value: "8.8.4.4",
                              italic: false,
                              disable: false,
                              alignment: "center",
                            },
                          ],
                          disable: false,
                          alignment: "center",
                        },
                      ],
                      alignment: "around",
                    },
                  },
                ],
                status: "SUCCESS",
                errors: [],
                start_time: "2023-05-30T14:03:21.873898Z",
                end_time: "2023-05-30T14:03:21.915887Z",
                runtime_configuration: {},
                type: "visualizer",
              },
              {
                id: 106,
                name: "test visualizer 2",
                process_time: 0.04,
                report: [
                  {
                    level: 1,
                    elements: {
                      type: "horizontal_list",
                      values: [
                        {
                          bold: false,
                          icon: "",
                          link: "",
                          size: "auto",
                          type: "base",
                          color: "",
                          value: "test component visualizer 2",
                          italic: false,
                          disable: false,
                          alignment: "center",
                        },
                      ],
                      alignment: "around",
                    },
                  },
                ],
                status: "SUCCESS",
                errors: [],
                start_time: "2023-05-30T14:03:21.873898Z",
                end_time: "2023-05-30T14:03:21.915887Z",
                runtime_configuration: {},
                type: "visualizer",
              },
            ],
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
            playbook_requested: null,
            playbook_to_execute: null,
            analyzers_requested: ["Classic_DNS"],
            connectors_requested: ["MISP", "OpenCTI", "Slack", "YETI"],
            analyzers_to_execute: ["Classic_DNS"],
            connectors_to_execute: [],
            visualizers_to_execute: [],
          }}
        />
      </BrowserRouter>
    );

    const visualizerButton = screen.getByRole("button", { name: "Visualizer" });
    expect(visualizerButton).toBeInTheDocument();
    const rawButton = screen.getByRole("button", { name: "Raw" });
    expect(rawButton).toBeInTheDocument();

    /** check start with the "test visualizer" visualizer UI */
    // check selected section
    expect(visualizerButton.className).toContain("btn-primary"); // selected
    expect(rawButton.className).toContain("btn-outline-tertiary"); // not selected
    // check nav
    const firstVisualizerMenuElement = screen.getByText("test visualizer");
    expect(firstVisualizerMenuElement).toBeInTheDocument();
    const secondVisualizerMenuElement = screen.getByText("test visualizer 2");
    expect(secondVisualizerMenuElement).toBeInTheDocument();
    expect(firstVisualizerMenuElement.closest("a").className).toContain(
      "active"
    );
    expect(secondVisualizerMenuElement.closest("a").className).not.toContain(
      "active"
    );
    // check tabs selection
    const firstVisualizerBody = container.querySelector("#jobReportTab105");
    const secondVisualizerBody = container.querySelector("#jobReportTab106");
    expect(firstVisualizerBody.className).toContain("active");
    expect(secondVisualizerBody.className).not.toContain("active");

    // check visualizer are in the correct tab
    expect(
      within(firstVisualizerBody).getByText("Classic DNS (2)")
    ).toBeInTheDocument();
    expect(
      within(secondVisualizerBody).getByText("test component visualizer 2")
    ).toBeInTheDocument();

    /** check the the "test visualizer 2" visualizer UI */
    await user.click(secondVisualizerMenuElement);
    // check sections
    expect(visualizerButton.className).toContain("btn-primary"); // selected
    expect(rawButton.className).toContain("btn-outline-tertiary"); // not selected
    // check nav
    expect(firstVisualizerMenuElement.closest("a").className).not.toContain(
      "active"
    );
    expect(secondVisualizerMenuElement.closest("a").className).toContain(
      "active"
    );
    // check tabs
    expect(firstVisualizerBody.className).not.toContain("active");
    expect(secondVisualizerBody.className).toContain("active");

    /**  move to the "raw" section (check analyzer reports) */
    await user.click(rawButton);
    // check sections
    expect(visualizerButton.className).toContain("btn-outline-tertiary"); // selected
    expect(rawButton.className).toContain("btn-primary"); // not selected
    // check nav
    const analyzerReportMenuElement = screen.getByText("Analyzers Report");
    expect(analyzerReportMenuElement).toBeInTheDocument();
    const connectorsReportMenuElement = screen.getByText("Connectors Report");
    expect(connectorsReportMenuElement).toBeInTheDocument();
    const visualizersReportMenuElement = screen.getByText("Visualizers Report");
    expect(visualizersReportMenuElement).toBeInTheDocument();
    expect(analyzerReportMenuElement.closest("a").className).toContain(
      "active"
    );
    expect(connectorsReportMenuElement.closest("a").className).not.toContain(
      "active"
    );
    expect(visualizersReportMenuElement.closest("a").className).not.toContain(
      "active"
    );
    // check tabs
    const analyzerReportBody = container.querySelector("#jobReportTab1");
    const connectorReportBody = container.querySelector("#jobReportTab2");
    const visualizerReportBody = container.querySelector("#jobReportTab3");
    expect(analyzerReportBody.className).toContain("active");
    expect(connectorReportBody.className).not.toContain("active");
    expect(visualizerReportBody.className).not.toContain("active");

    /** move to connector reports */
    await user.click(connectorsReportMenuElement);
    // check sections
    expect(visualizerButton.className).toContain("btn-outline-tertiary"); // selected
    expect(rawButton.className).toContain("btn-primary"); // not selected
    // check nav
    expect(analyzerReportMenuElement.closest("a").className).not.toContain(
      "active"
    );
    expect(connectorsReportMenuElement.closest("a").className).toContain(
      "active"
    );
    expect(visualizersReportMenuElement.closest("a").className).not.toContain(
      "active"
    );
    // check tabs
    expect(analyzerReportBody.className).not.toContain("active");
    expect(connectorReportBody.className).toContain("active");
    expect(visualizerReportBody.className).not.toContain("active");

    /** move to visualizer reports */
    await user.click(visualizersReportMenuElement);
    // check sections
    expect(visualizerButton.className).toContain("btn-outline-tertiary"); // selected
    expect(rawButton.className).toContain("btn-primary"); // not selected
    // check nav
    expect(analyzerReportMenuElement.closest("a").className).not.toContain(
      "active"
    );
    expect(connectorsReportMenuElement.closest("a").className).not.toContain(
      "active"
    );
    expect(visualizersReportMenuElement.closest("a").className).toContain(
      "active"
    );
    // check tabs
    expect(analyzerReportBody.className).not.toContain("active");
    expect(connectorReportBody.className).not.toContain("active");
    expect(visualizerReportBody.className).toContain("active");

    /** go back to visualizer UI (check "test visualizer" is selected again) */
    await user.click(visualizerButton);
    // check sections
    expect(visualizerButton.className).toContain("btn-primary"); // not selected
    expect(rawButton.className).toContain("btn-outline-tertiary"); // selected
    // check navs
    expect(firstVisualizerMenuElement.closest("a").className).toContain(
      "active"
    );
    expect(secondVisualizerMenuElement.closest("a").className).not.toContain(
      "active"
    );
    // check tabs selection
    expect(firstVisualizerBody.className).toContain("active");
    expect(secondVisualizerBody.className).not.toContain("active");
  });
});
