import React from "react";
import "@testing-library/jest-dom";
import { render, screen, within } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import { JobOverview } from "../../../../src/components/jobs/result/JobOverview";

// mock flow component
jest.mock("../../../../src/components/jobs/result/JobIsRunningAlert", () => ({
  JobIsRunningAlert: jest.fn((props) => <div {...props} />),
}));

describe("test JobOverview (job report)", () => {
  test("JobOverview components", () => {
    const { container } = render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          section="raw"
          subSection="analyzer"
          refetch={() => {}}
          job={{
            id: 2,
            user: {
              username: "test",
            },
            tags: [],
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
              pivots: {},
              visualizers: {},
            },
            received_request_time: "2023-05-31T08:19:03.256003",
            finished_analysis_time: "2023-05-31T08:19:04.484684",
            process_time: 0.23,
            tlp: "AMBER",
            warnings: [],
            errors: [],
            analyzers_requested: ["Classic_DNS"],
            analyzers_to_execute: [],
            analyzer_reports: [],
            connectors_requested: ["MISP", "OpenCTI", "Slack", "YETI"],
            connectors_to_execute: [],
            connector_reports: [],
            pivots_requested: [],
            pivots_to_execute: [],
            pivot_reports: [],
            visualizers_requested: [],
            visualizers_to_execute: [],
            visualizer_reports: [],
            playbook_requested: null,
            playbook_to_execute: null,
          }}
        />
      </BrowserRouter>,
    );

    // Page title
    expect(screen.getByRole("heading", { name: "Job #2" })).toBeInTheDocument();
    // status
    expect(
      container.querySelector("#statusicon-reported_without_fails"),
    ).toBeInTheDocument();
    // actions bar
    expect(container.querySelector("#utilitiesRow")).toBeInTheDocument();
    // info card
    const JobInfoCardSection = container.querySelector("#JobInfoCardSection");
    expect(JobInfoCardSection).toBeInTheDocument();
    // name
    expect(
      screen.getByRole("heading", { name: "dns.google.com" }),
    ).toBeInTheDocument();
    // dropdown button
    const JobInfoCardDropDownButton = container.querySelector(
      "#JobInfoCardDropDown",
    );
    expect(JobInfoCardDropDownButton).toBeInTheDocument();
  });

  test("test utility bar", () => {
    const { container } = render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          section="raw"
          subSection="analyzer"
          refetch={() => {}}
          job={{
            id: 1,
            user: {
              username: "test",
            },
            tags: [],
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
              pivots: {},
              visualizers: {},
            },
            received_request_time: "2023-05-31T08:19:03.256003",
            finished_analysis_time: "2023-05-31T08:19:04.484684",
            process_time: 0.23,
            tlp: "AMBER",
            warnings: [],
            errors: [],
            analyzers_requested: ["Classic_DNS"],
            analyzers_to_execute: [],
            analyzer_reports: [],
            connectors_requested: ["MISP", "OpenCTI", "Slack", "YETI"],
            connectors_to_execute: [],
            connector_reports: [],
            pivots_requested: [],
            pivots_to_execute: [],
            pivot_reports: [],
            visualizers_requested: [],
            visualizers_to_execute: [],
            visualizer_reports: [],
            playbook_requested: "TestPlaybook",
            playbook_to_execute: "TestPlaybook",
          }}
        />
      </BrowserRouter>,
    );

    // utility bar
    const utilitiesRow = container.querySelector("#utilitiesRow");
    expect(within(utilitiesRow).getByText("Job #1")).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Comments (1)" }),
    ).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Delete" }),
    ).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Rescan" }),
    ).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Save As Playbook" }),
    ).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Report" }),
    ).toBeInTheDocument();
  });

  test("investigation overview button", () => {
    const { container } = render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          section="raw"
          subSection="analyzer"
          refetch={() => {}}
          job={{
            id: 2,
            user: {
              username: "test",
            },
            tags: [],
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
              pivots: {},
              visualizers: {},
            },
            received_request_time: "2023-05-31T08:19:03.256003",
            finished_analysis_time: "2023-05-31T08:19:04.484684",
            process_time: 0.23,
            tlp: "AMBER",
            warnings: [],
            errors: [],
            analyzers_requested: ["Classic_DNS"],
            analyzers_to_execute: [],
            analyzer_reports: [],
            connectors_requested: ["MISP", "OpenCTI", "Slack", "YETI"],
            connectors_to_execute: [],
            connector_reports: [],
            pivots_requested: [],
            pivots_to_execute: [],
            pivot_reports: [],
            visualizers_requested: [],
            visualizers_to_execute: [],
            visualizer_reports: [],
            playbook_requested: "TestPlaybook",
            playbook_to_execute: "TestPlaybook",
            investigation: 1,
            investigation_id: 1,
            investigation_name: "test investigation",
            related_investigation_number: 10,
          }}
        />
      </BrowserRouter>,
    );
    // once we know the JobInfoCard Component is load the check about it is the proper file
    const JobInfoCardSection = container.querySelector("#JobInfoCardSection");
    expect(JobInfoCardSection).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("dns.google.com"),
    ).toBeInTheDocument();
  });

  test("move from raw to visualizer-Test page", async () => {
    render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          section="raw"
          subSection="analyzer"
          refetch={() => {}}
          job={{
            id: 3,
            user: {
              username: "test",
            },
            tags: [],
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
              pivots: {},
              visualizers: {},
            },
            received_request_time: "2023-05-31T08:19:03.256003",
            finished_analysis_time: "2023-05-31T08:19:04.484684",
            process_time: 0.23,
            tlp: "AMBER",
            warnings: [],
            errors: [],
            analyzers_requested: ["Classic_DNS"],
            analyzers_to_execute: [],
            analyzer_reports: [],
            connectors_requested: ["MISP", "OpenCTI", "Slack", "YETI"],
            connectors_to_execute: [],
            connector_reports: [],
            pivots_requested: [],
            pivots_to_execute: [],
            pivot_reports: [],
            visualizers_requested: ["TestVisualizer"],
            visualizers_to_execute: ["TestVisualizer"],
            visualizer_reports: [
              {
                id: 730,
                name: "Test_page_1",
                process_time: 0.0,
                status: "SUCCESS",
                warnings: [],
                errors: [],
                start_time: "2023-10-05T15:57:51.350841Z",
                end_time: "2023-10-05T15:57:51.547472Z",
                runtime_configuration: {},
                config: "TestVisualizer",
                type: "visualizer",
                report: [
                  {
                    level: 1,
                    elements: {
                      type: "horizontal_list",
                      values: [],
                    },
                  },
                ],
              },
            ],
            playbook_requested: "TestPlaybook",
            playbook_to_execute: "TestPlaybook",
          }}
        />
      </BrowserRouter>,
    );
    const user = userEvent.setup();

    // check sections visualizer/raw
    const visualizerButton = screen.getByRole("button", { name: "Visualizer" });
    expect(visualizerButton).toBeInTheDocument();
    expect(visualizerButton.className).toContain("btn-outline-tertiary"); // not selected
    const rawButton = screen.getByRole("button", { name: "Raw" });
    expect(rawButton).toBeInTheDocument();
    expect(rawButton.className).toContain("btn-primary"); // selected
    // check subsections available
    const analyzerReport = screen.getByText("Analyzers Report");
    expect(analyzerReport).toBeInTheDocument();
    const connectorReport = screen.getByText("Connectors Report");
    expect(connectorReport).toBeInTheDocument();
    const pivotReport = screen.getByText("Pivots Report");
    expect(pivotReport).toBeInTheDocument();
    const visualizerReport = screen.getByText("Visualizers Report");
    expect(visualizerReport).toBeInTheDocument();
    const fullReport = screen.getByText("Full Report");
    expect(fullReport).toBeInTheDocument();
    // check active subsection
    expect(analyzerReport.closest("a").className).toContain("active");
    expect(connectorReport.closest("a").className).not.toContain("active");
    expect(pivotReport.closest("a").className).not.toContain("active");
    expect(visualizerReport.closest("a").className).not.toContain("active");
    expect(fullReport.closest("a").className).not.toContain("active");

    await user.click(visualizerButton);
  });

  test("move from raw to visualizer-loading", async () => {
    render(
      <BrowserRouter>
        <JobOverview
          isRunningJob
          section="raw"
          subSection="analyzer"
          refetch={() => {}}
          job={{
            id: 4,
            user: {
              username: "test",
            },
            tags: [],
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
            status: "running",
            runtime_configuration: {
              analyzers: {},
              connectors: {},
              pivots: {},
              visualizers: {},
            },
            received_request_time: "2023-05-31T08:19:03.256003",
            finished_analysis_time: "2023-05-31T08:19:04.484684",
            process_time: 0.23,
            tlp: "AMBER",
            warnings: [],
            errors: [],
            analyzers_requested: ["Classic_DNS"],
            analyzers_to_execute: [],
            analyzer_reports: [],
            connectors_requested: ["MISP", "OpenCTI", "Slack", "YETI"],
            connectors_to_execute: [],
            connector_reports: [],
            pivots_requested: [],
            pivots_to_execute: [],
            pivot_reports: [],
            visualizers_requested: ["TestVisualizer"],
            visualizers_to_execute: ["TestVisualizer"],
            visualizer_reports: [
              {
                id: 730,
                name: "Test_page_1",
                process_time: 0.0,
                status: "RUNNING",
                warnings: [],
                errors: [],
                start_time: "2023-10-05T15:57:51.350841Z",
                end_time: "2023-10-05T15:57:51.547472Z",
                runtime_configuration: {},
                config: "TestVisualizer",
                type: "visualizer",
                report: [],
              },
            ],
            playbook_requested: "TestPlaybook",
            playbook_to_execute: "TestPlaybook",
          }}
        />
      </BrowserRouter>,
    );
    const user = userEvent.setup();

    // check sections visualizer/raw
    const visualizerButton = screen.getByRole("button", { name: "Visualizer" });
    expect(visualizerButton).toBeInTheDocument();
    expect(visualizerButton.className).toContain("btn-outline-tertiary"); // not selected
    const rawButton = screen.getByRole("button", { name: "Raw" });
    expect(rawButton).toBeInTheDocument();
    expect(rawButton.className).toContain("btn-primary"); // selected
    // check subsections available
    const analyzerReport = screen.getByText("Analyzers Report");
    expect(analyzerReport).toBeInTheDocument();
    const connectorReport = screen.getByText("Connectors Report");
    expect(connectorReport).toBeInTheDocument();
    const pivotReport = screen.getByText("Pivots Report");
    expect(pivotReport).toBeInTheDocument();
    const visualizerReport = screen.getByText("Visualizers Report");
    expect(visualizerReport).toBeInTheDocument();
    const fullReport = screen.getByText("Full Report");
    expect(fullReport).toBeInTheDocument();
    // check active subsection
    expect(analyzerReport.closest("a").className).toContain("active");
    expect(connectorReport.closest("a").className).not.toContain("active");
    expect(pivotReport.closest("a").className).not.toContain("active");
    expect(visualizerReport.closest("a").className).not.toContain("active");
    expect(fullReport.closest("a").className).not.toContain("active");

    await user.click(visualizerButton);
  });

  test("move from raw to visualizer-no_visualizer", async () => {
    render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          section="raw"
          subSection="analyzer"
          refetch={() => {}}
          job={{
            id: 5,
            user: {
              username: "test",
            },
            tags: [],
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
              pivots: {},
              visualizers: {},
            },
            received_request_time: "2023-05-31T08:19:03.256003",
            finished_analysis_time: "2023-05-31T08:19:04.484684",
            process_time: 0.23,
            tlp: "AMBER",
            warnings: [],
            errors: [],
            analyzers_requested: ["Classic_DNS"],
            analyzers_to_execute: [],
            analyzer_reports: [],
            connectors_requested: ["MISP", "OpenCTI", "Slack", "YETI"],
            connectors_to_execute: [],
            connector_reports: [],
            pivots_requested: [],
            pivots_to_execute: [],
            pivot_reports: [],
            visualizers_requested: [],
            visualizers_to_execute: [],
            visualizer_reports: [],
            playbook_requested: "TestPlaybook",
            playbook_to_execute: "TestPlaybook",
          }}
        />
      </BrowserRouter>,
    );
    const user = userEvent.setup();

    // check sections visualizer/raw
    const visualizerButton = screen.getByRole("button", { name: "Visualizer" });
    expect(visualizerButton).toBeInTheDocument();
    expect(visualizerButton.className).toContain("btn-outline-tertiary"); // not selected
    const rawButton = screen.getByRole("button", { name: "Raw" });
    expect(rawButton).toBeInTheDocument();
    expect(rawButton.className).toContain("btn-primary"); // selected
    // check subsections available
    const analyzerReport = screen.getByText("Analyzers Report");
    expect(analyzerReport).toBeInTheDocument();
    const connectorReport = screen.getByText("Connectors Report");
    expect(connectorReport).toBeInTheDocument();
    const pivotReport = screen.getByText("Pivots Report");
    expect(pivotReport).toBeInTheDocument();
    const visualizerReport = screen.getByText("Visualizers Report");
    expect(visualizerReport).toBeInTheDocument();
    const fullReport = screen.getByText("Full Report");
    expect(fullReport).toBeInTheDocument();
    // check active subsection
    expect(analyzerReport.closest("a").className).toContain("active");
    expect(connectorReport.closest("a").className).not.toContain("active");
    expect(pivotReport.closest("a").className).not.toContain("active");
    expect(visualizerReport.closest("a").className).not.toContain("active");
    expect(fullReport.closest("a").className).not.toContain("active");

    await user.click(visualizerButton);
  });

  test("move from visualizer-Test page 1/2 to visualizer-Test page 2/2", async () => {
    render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          section="visualizer"
          subSection="Test page 1/2"
          refetch={() => {}}
          job={{
            id: 6,
            user: {
              username: "test",
            },
            tags: [],
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
              pivots: {},
              visualizers: {},
            },
            received_request_time: "2023-05-31T08:19:03.256003",
            finished_analysis_time: "2023-05-31T08:19:04.484684",
            process_time: 0.23,
            tlp: "AMBER",
            warnings: [],
            errors: [],
            analyzers_requested: ["Classic_DNS"],
            analyzers_to_execute: [],
            analyzer_reports: [],
            connectors_requested: ["MISP", "OpenCTI", "Slack", "YETI"],
            connectors_to_execute: [],
            connector_reports: [],
            pivots_requested: [],
            pivots_to_execute: [],
            pivot_reports: [],
            visualizers_requested: ["TestVisualizer"],
            visualizers_to_execute: ["TestVisualizer"],
            visualizer_reports: [
              {
                id: 730,
                name: "Test page 1/2",
                process_time: 0.0,
                status: "SUCCESS",
                warnings: [],
                errors: [],
                start_time: "2023-10-05T15:57:51.350841Z",
                end_time: "2023-10-05T15:57:51.547472Z",
                runtime_configuration: {},
                config: "TestVisualizer",
                type: "visualizer",
                report: [
                  {
                    level: 1,
                    elements: {
                      type: "horizontal_list",
                      values: [],
                    },
                  },
                ],
              },
              {
                id: 731,
                name: "Test page 2/2",
                process_time: 0.0,
                status: "SUCCESS",
                warnings: [],
                errors: [],
                start_time: "2023-10-05T15:57:51.350841Z",
                end_time: "2023-10-05T15:57:51.547472Z",
                runtime_configuration: {},
                config: "TestVisualizer",
                type: "visualizer",
                report: [
                  {
                    level: 1,
                    elements: {
                      type: "horizontal_list",
                      values: [],
                    },
                  },
                ],
              },
            ],
            playbook_requested: "TestPlaybook",
            playbook_to_execute: "TestPlaybook",
          }}
        />
      </BrowserRouter>,
    );
    const user = userEvent.setup();

    // check sections visualizer/raw
    const visualizerButton = screen.getByRole("button", { name: "Visualizer" });
    expect(visualizerButton).toBeInTheDocument();
    expect(visualizerButton.className).toContain("btn-primary"); // selected
    const rawButton = screen.getByRole("button", { name: "Raw" });
    expect(rawButton).toBeInTheDocument();
    expect(rawButton.className).toContain("btn-outline-tertiary"); // not selected
    // check subsections available
    const firstPageReport = screen.getByText("Test page 1/2");
    expect(firstPageReport).toBeInTheDocument();
    const secondPageReport = screen.getByText("Test page 2/2");
    expect(secondPageReport).toBeInTheDocument();
    // check active subsection
    expect(firstPageReport.closest("a").className).toContain("active");
    expect(secondPageReport.closest("a").className).not.toContain("active");

    await user.click(secondPageReport);
  });

  test("move from visualizer-Test page 1 to raw-analyzer", async () => {
    render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          section="visualizer"
          subSection="Test page 1"
          refetch={() => {}}
          job={{
            id: 7,
            user: {
              username: "test",
            },
            tags: [],
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
              pivots: {},
              visualizers: {},
            },
            received_request_time: "2023-05-31T08:19:03.256003",
            finished_analysis_time: "2023-05-31T08:19:04.484684",
            process_time: 0.23,
            tlp: "AMBER",
            warnings: [],
            errors: [],
            analyzers_requested: ["Classic_DNS"],
            analyzers_to_execute: [],
            analyzer_reports: [],
            connectors_requested: ["MISP", "OpenCTI", "Slack", "YETI"],
            connectors_to_execute: [],
            connector_reports: [],
            pivots_requested: [],
            pivots_to_execute: [],
            pivot_reports: [],
            visualizers_requested: ["TestVisualizer"],
            visualizers_to_execute: ["TestVisualizer"],
            visualizer_reports: [
              {
                id: 730,
                name: "Test page 1",
                process_time: 0.0,
                status: "SUCCESS",
                warnings: [],
                errors: [],
                start_time: "2023-10-05T15:57:51.350841Z",
                end_time: "2023-10-05T15:57:51.547472Z",
                runtime_configuration: {},
                config: "TestVisualizer",
                type: "visualizer",
                report: [
                  {
                    level: 1,
                    elements: {
                      type: "horizontal_list",
                      values: [],
                    },
                  },
                ],
              },
            ],
            playbook_requested: "TestPlaybook",
            playbook_to_execute: "TestPlaybook",
          }}
        />
      </BrowserRouter>,
    );
    const user = userEvent.setup();

    // check sections visualizer/raw
    const visualizerButton = screen.getByRole("button", { name: "Visualizer" });
    expect(visualizerButton).toBeInTheDocument();
    expect(visualizerButton.className).toContain("btn-primary"); // selected
    const rawButton = screen.getByRole("button", { name: "Raw" });
    expect(rawButton).toBeInTheDocument();
    expect(rawButton.className).toContain("btn-outline-tertiary"); // not selected
    // check subsections available
    const firstPageReport = screen.getByText("Test page 1");
    expect(firstPageReport).toBeInTheDocument();
    // check active subsection
    expect(firstPageReport.closest("a").className).toContain("active");

    await user.click(rawButton);
  });

  test("move from raw-analyzer to raw-connector", async () => {
    render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          section="raw"
          subSection="analyzer"
          refetch={() => {}}
          job={{
            id: 8,
            user: {
              username: "test",
            },
            tags: [],
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
              pivots: {},
              visualizers: {},
            },
            received_request_time: "2023-05-31T08:19:03.256003",
            finished_analysis_time: "2023-05-31T08:19:04.484684",
            process_time: 0.23,
            tlp: "AMBER",
            warnings: [],
            errors: [],
            analyzers_requested: ["Classic_DNS"],
            analyzers_to_execute: [],
            analyzer_reports: [],
            connectors_requested: ["MISP", "OpenCTI", "Slack", "YETI"],
            connectors_to_execute: [],
            connector_reports: [],
            pivots_requested: [],
            pivots_to_execute: [],
            pivot_reports: [],
            visualizers_requested: [],
            visualizers_to_execute: [],
            visualizer_reports: [],
            playbook_requested: "TestPlaybook",
            playbook_to_execute: "TestPlaybook",
          }}
        />
      </BrowserRouter>,
    );
    const user = userEvent.setup();

    // check sections visualizer/raw
    const visualizerButton = screen.getByRole("button", { name: "Visualizer" });
    expect(visualizerButton).toBeInTheDocument();
    expect(visualizerButton.className).toContain("btn-outline-tertiary"); // not selected
    const rawButton = screen.getByRole("button", { name: "Raw" });
    expect(rawButton).toBeInTheDocument();
    expect(rawButton.className).toContain("btn-primary"); // selected
    // check subsections available
    const analyzerReport = screen.getByText("Analyzers Report");
    expect(analyzerReport).toBeInTheDocument();
    const connectorReport = screen.getByText("Connectors Report");
    expect(connectorReport).toBeInTheDocument();
    const pivotReport = screen.getByText("Pivots Report");
    expect(pivotReport).toBeInTheDocument();
    const visualizerReport = screen.getByText("Visualizers Report");
    expect(visualizerReport).toBeInTheDocument();
    const fullReport = screen.getByText("Full Report");
    expect(fullReport).toBeInTheDocument();
    // check active subsection
    expect(analyzerReport.closest("a").className).toContain("active");
    expect(connectorReport.closest("a").className).not.toContain("active");
    expect(pivotReport.closest("a").className).not.toContain("active");
    expect(visualizerReport.closest("a").className).not.toContain("active");
    expect(fullReport.closest("a").className).not.toContain("active");

    await user.click(connectorReport);
  });

  test("move from raw-analyzer to raw-pivot", async () => {
    render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          section="raw"
          subSection="analyzer"
          refetch={() => {}}
          job={{
            id: 9,
            user: {
              username: "test",
            },
            tags: [],
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
              pivots: {},
              visualizers: {},
            },
            received_request_time: "2023-05-31T08:19:03.256003",
            finished_analysis_time: "2023-05-31T08:19:04.484684",
            process_time: 0.23,
            tlp: "AMBER",
            warnings: [],
            errors: [],
            analyzers_requested: ["Classic_DNS"],
            analyzers_to_execute: [],
            analyzer_reports: [],
            connectors_requested: ["MISP", "OpenCTI", "Slack", "YETI"],
            connectors_to_execute: [],
            connector_reports: [],
            pivots_requested: [],
            pivots_to_execute: [],
            pivot_reports: [],
            visualizers_requested: [],
            visualizers_to_execute: [],
            visualizer_reports: [],
            playbook_requested: "TestPlaybook",
            playbook_to_execute: "TestPlaybook",
          }}
        />
      </BrowserRouter>,
    );
    const user = userEvent.setup();

    // check sections visualizer/raw
    const visualizerButton = screen.getByRole("button", { name: "Visualizer" });
    expect(visualizerButton).toBeInTheDocument();
    expect(visualizerButton.className).toContain("btn-outline-tertiary"); // not selected
    const rawButton = screen.getByRole("button", { name: "Raw" });
    expect(rawButton).toBeInTheDocument();
    expect(rawButton.className).toContain("btn-primary"); // selected
    // check subsections available
    const analyzerReport = screen.getByText("Analyzers Report");
    expect(analyzerReport).toBeInTheDocument();
    const connectorReport = screen.getByText("Connectors Report");
    expect(connectorReport).toBeInTheDocument();
    const pivotReport = screen.getByText("Pivots Report");
    expect(pivotReport).toBeInTheDocument();
    const visualizerReport = screen.getByText("Visualizers Report");
    expect(visualizerReport).toBeInTheDocument();
    const fullReport = screen.getByText("Full Report");
    expect(fullReport).toBeInTheDocument();
    // check active subsection
    expect(analyzerReport.closest("a").className).toContain("active");
    expect(connectorReport.closest("a").className).not.toContain("active");
    expect(pivotReport.closest("a").className).not.toContain("active");
    expect(visualizerReport.closest("a").className).not.toContain("active");
    expect(fullReport.closest("a").className).not.toContain("active");

    await user.click(pivotReport);
  });

  test("move from raw-analyzer to raw-visualizer", async () => {
    render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          section="raw"
          subSection="analyzer"
          refetch={() => {}}
          job={{
            id: 10,
            user: {
              username: "test",
            },
            tags: [],
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
              pivots: {},
              visualizers: {},
            },
            received_request_time: "2023-05-31T08:19:03.256003",
            finished_analysis_time: "2023-05-31T08:19:04.484684",
            process_time: 0.23,
            tlp: "AMBER",
            warnings: [],
            errors: [],
            analyzers_requested: ["Classic_DNS"],
            analyzers_to_execute: [],
            analyzer_reports: [],
            connectors_requested: ["MISP", "OpenCTI", "Slack", "YETI"],
            connectors_to_execute: [],
            connector_reports: [],
            pivots_requested: [],
            pivots_to_execute: [],
            pivot_reports: [],
            visualizers_requested: [],
            visualizers_to_execute: [],
            visualizer_reports: [],
            playbook_requested: "TestPlaybook",
            playbook_to_execute: "TestPlaybook",
          }}
        />
      </BrowserRouter>,
    );
    const user = userEvent.setup();

    // check sections visualizer/raw
    const visualizerButton = screen.getByRole("button", { name: "Visualizer" });
    expect(visualizerButton).toBeInTheDocument();
    expect(visualizerButton.className).toContain("btn-outline-tertiary"); // not selected
    const rawButton = screen.getByRole("button", { name: "Raw" });
    expect(rawButton).toBeInTheDocument();
    expect(rawButton.className).toContain("btn-primary"); // selected
    // check subsections available
    const analyzerReport = screen.getByText("Analyzers Report");
    expect(analyzerReport).toBeInTheDocument();
    const connectorReport = screen.getByText("Connectors Report");
    expect(connectorReport).toBeInTheDocument();
    const pivotReport = screen.getByText("Pivots Report");
    expect(pivotReport).toBeInTheDocument();
    const visualizerReport = screen.getByText("Visualizers Report");
    expect(visualizerReport).toBeInTheDocument();
    const fullReport = screen.getByText("Full Report");
    expect(fullReport).toBeInTheDocument();
    // check active subsection
    expect(analyzerReport.closest("a").className).toContain("active");
    expect(connectorReport.closest("a").className).not.toContain("active");
    expect(pivotReport.closest("a").className).not.toContain("active");
    expect(visualizerReport.closest("a").className).not.toContain("active");
    expect(fullReport.closest("a").className).not.toContain("active");

    await user.click(visualizerReport);
  });

  test("move from raw-analyzer to raw-full", async () => {
    const { container } = render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          section="raw"
          subSection="analyzer"
          refetch={() => {}}
          job={{
            id: 10,
            user: {
              username: "test",
            },
            tags: [],
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
              pivots: {},
              visualizers: {},
            },
            received_request_time: "2023-05-31T08:19:03.256003",
            finished_analysis_time: "2023-05-31T08:19:04.484684",
            process_time: 0.23,
            tlp: "AMBER",
            warnings: [],
            errors: [],
            analyzers_requested: ["Classic_DNS"],
            analyzers_to_execute: [],
            analyzer_reports: [],
            connectors_requested: ["MISP", "OpenCTI", "Slack", "YETI"],
            connectors_to_execute: [],
            connector_reports: [],
            pivots_requested: [],
            pivots_to_execute: [],
            pivot_reports: [],
            visualizers_requested: [],
            visualizers_to_execute: [],
            visualizer_reports: [],
            playbook_requested: "TestPlaybook",
            playbook_to_execute: "TestPlaybook",
          }}
        />
      </BrowserRouter>,
    );
    const user = userEvent.setup();

    // check sections visualizer/raw
    const visualizerButton = screen.getByRole("button", { name: "Visualizer" });
    expect(visualizerButton).toBeInTheDocument();
    expect(visualizerButton.className).toContain("btn-outline-tertiary"); // not selected
    const rawButton = screen.getByRole("button", { name: "Raw" });
    expect(rawButton).toBeInTheDocument();
    expect(rawButton.className).toContain("btn-primary"); // selected
    // check subsections available
    const analyzerReport = screen.getByText("Analyzers Report");
    expect(analyzerReport).toBeInTheDocument();
    const connectorReport = screen.getByText("Connectors Report");
    expect(connectorReport).toBeInTheDocument();
    const pivotReport = screen.getByText("Pivots Report");
    expect(pivotReport).toBeInTheDocument();
    const visualizerReport = screen.getByText("Visualizers Report");
    expect(visualizerReport).toBeInTheDocument();
    const fullReport = screen.getByText("Full Report");
    expect(fullReport).toBeInTheDocument();
    // check active subsection
    expect(analyzerReport.closest("a").className).toContain("active");
    expect(connectorReport.closest("a").className).not.toContain("active");
    expect(pivotReport.closest("a").className).not.toContain("active");
    expect(visualizerReport.closest("a").className).not.toContain("active");
    expect(fullReport.closest("a").className).not.toContain("active");

    await user.click(fullReport);
    const fullReportSection = container.querySelector(
      `#jobfullreport-jsoninput-10`,
    );
    expect(fullReportSection).toBeInTheDocument();
  });

  test("move from raw-visualizer to raw-analyzer", async () => {
    render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          section="raw"
          subSection="visualizer"
          refetch={() => {}}
          job={{
            id: 11,
            user: {
              username: "test",
            },
            tags: [],
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
              pivots: {},
              visualizers: {},
            },
            received_request_time: "2023-05-31T08:19:03.256003",
            finished_analysis_time: "2023-05-31T08:19:04.484684",
            process_time: 0.23,
            tlp: "AMBER",
            warnings: [],
            errors: [],
            analyzers_requested: ["Classic_DNS"],
            analyzers_to_execute: [],
            analyzer_reports: [],
            connectors_requested: ["MISP", "OpenCTI", "Slack", "YETI"],
            connectors_to_execute: [],
            connector_reports: [],
            pivots_requested: [],
            pivots_to_execute: [],
            pivot_reports: [],
            visualizers_requested: [],
            visualizers_to_execute: [],
            visualizer_reports: [],
            playbook_requested: "TestPlaybook",
            playbook_to_execute: "TestPlaybook",
          }}
        />
      </BrowserRouter>,
    );
    const user = userEvent.setup();

    // check sections visualizer/raw
    const visualizerButton = screen.getByRole("button", { name: "Visualizer" });
    expect(visualizerButton).toBeInTheDocument();
    expect(visualizerButton.className).toContain("btn-outline-tertiary"); // not selected
    const rawButton = screen.getByRole("button", { name: "Raw" });
    expect(rawButton).toBeInTheDocument();
    expect(rawButton.className).toContain("btn-primary"); // selected
    // check subsections available
    const analyzerReport = screen.getByText("Analyzers Report");
    expect(analyzerReport).toBeInTheDocument();
    const connectorReport = screen.getByText("Connectors Report");
    expect(connectorReport).toBeInTheDocument();
    const pivotReport = screen.getByText("Pivots Report");
    expect(pivotReport).toBeInTheDocument();
    const visualizerReport = screen.getByText("Visualizers Report");
    expect(visualizerReport).toBeInTheDocument();
    const fullReport = screen.getByText("Full Report");
    expect(fullReport).toBeInTheDocument();
    // check active subsection
    expect(analyzerReport.closest("a").className).not.toContain("active");
    expect(connectorReport.closest("a").className).not.toContain("active");
    expect(pivotReport.closest("a").className).not.toContain("active");
    expect(visualizerReport.closest("a").className).toContain("active");
    expect(fullReport.closest("a").className).not.toContain("active");

    await user.click(analyzerReport);
  });
});
