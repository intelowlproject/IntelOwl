import React from "react";
import "@testing-library/jest-dom";
import { render, screen, within, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import { JobOverview } from "../../../../../src/components/jobs/result/utils";

describe("test JobOverview (job report)", () => {

  test("test utility bar", () => {
    const { container } = render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          section="raw"
          subSection="analyzer"
          refetch={() => {}}
          job={{
            id: 108,
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

    // utility bar
    const utilitiesRow = container.querySelector("#utilitiesRow");
    expect(within(utilitiesRow).getByText("Job #108")).toBeInTheDocument();
    const goBackButton = within(utilitiesRow).getByRole("button", { name: "" });
    expect(goBackButton.id).toBe("gobackbutton");
    expect(
      within(utilitiesRow).getByRole("button", { name: "Comments (1)" }),
    ).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Delete Job" }),
    ).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Rescan" }),
    ).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Save As Playbook" }),
    ).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Raw JSON" }),
    ).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Share" }),
    ).toBeInTheDocument();
  })

  test("metadata section", () => {
    const { container } = render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          section="raw"
          subSection="analyzer"
          refetch={() => {}}
          job={{
            id: 108,
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

    // metadata - first line
    const JobInfoCardSection = container.querySelector("#JobInfoCardSection");
    expect(
      within(JobInfoCardSection).getByText("dns.google.com"),
    ).toBeInTheDocument();
    const JobInfoCardDropDown = within(JobInfoCardSection).getByRole("button", {
      name: "",
    });
    expect(JobInfoCardDropDown.id).toBe("JobInfoCardDropDown");
    expect(within(JobInfoCardSection).getByText("Status")).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("REPORTED WITHOUT FAILS"),
    ).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("TLP")).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("AMBER")).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("User")).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("test")).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("MD5")).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("f9bc35a57b22f82c94dbcc420f71b903"),
    ).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("Process Time (mm:ss)"),
    ).toBeInTheDocument();
    expect(within(JobInfoCardSection).getByText("00:00")).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("Start Time"),
    ).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("08:19:03 AM May 31st, 2023"),
    ).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("End Time"),
    ).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("08:19:04 AM May 31st, 2023"),
    ).toBeInTheDocument();
    // metadata - second line
    expect(within(JobInfoCardSection).getByText("Tags")).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("Error(s)"),
    ).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("Playbook"),
    ).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("TestPlaybook"),
    ).toBeInTheDocument();
  })

  test("move from raw to visualizer-Test page", async() => {
    render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          section="raw"
          subSection="analyzer"
          refetch={() => {}}
          job={{
            id: 108,
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
                "id": 730,
                "name": "Test page 1",
                "process_time": 0.0,
                "status": "SUCCESS",
                "errors": [],
                "start_time": "2023-10-05T15:57:51.350841Z",
                "end_time": "2023-10-05T15:57:51.547472Z",
                "runtime_configuration": {},
                "config": "TestVisualizer",
                "type": "visualizer",
                "report": [
                  {
                    "level": 1,
                    "elements": {
                        "type": "horizontal_list",
                        "values": []
                    }
                  }
                ]
              }
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
    // check active subsection
    expect(analyzerReport.closest("a").className).toContain("active");
    expect(connectorReport.closest("a").className).not.toContain("active");
    expect(pivotReport.closest("a").className).not.toContain("active");
    expect(visualizerReport.closest("a").className).not.toContain("active");
    
    await user.click(visualizerButton)
    expect(global.location.pathname).toEqual("/jobs/108/visualizer/Test%20page%201");
  })

  test("move from raw to visualizer-loading", async() => {
    render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          section="raw"
          subSection="analyzer"
          refetch={() => {}}
          job={{
            id: 108,
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
                "id": 730,
                "name": "Test page 1",
                "process_time": 0.0,
                "status": "RUNNING",
                "errors": [],
                "start_time": "2023-10-05T15:57:51.350841Z",
                "end_time": "2023-10-05T15:57:51.547472Z",
                "runtime_configuration": {},
                "config": "TestVisualizer",
                "type": "visualizer",
                "report": []
              }
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
    // check active subsection
    expect(analyzerReport.closest("a").className).toContain("active");
    expect(connectorReport.closest("a").className).not.toContain("active");
    expect(pivotReport.closest("a").className).not.toContain("active");
    expect(visualizerReport.closest("a").className).not.toContain("active");
    
    await user.click(visualizerButton)
    expect(global.location.pathname).toEqual("/jobs/108/visualizer/loading");
  })

  test("move from raw to visualizer-no_visualizer", async() => {
    render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          section="raw"
          subSection="analyzer"
          refetch={() => {}}
          job={{
            id: 108,
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
    // check active subsection
    expect(analyzerReport.closest("a").className).toContain("active");
    expect(connectorReport.closest("a").className).not.toContain("active");
    expect(pivotReport.closest("a").className).not.toContain("active");
    expect(visualizerReport.closest("a").className).not.toContain("active");
    
    await user.click(visualizerButton)
    expect(global.location.pathname).toEqual("/jobs/108/visualizer/no-visualizer");
  })

  test("move from visualizer-Test page 1 to visualizer-Test page 2", async() => {
    render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          section="visualizer"
          subSection="Test page 1"
          refetch={() => {}}
          job={{
            id: 108,
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
                "id": 730,
                "name": "Test page 1",
                "process_time": 0.0,
                "status": "SUCCESS",
                "errors": [],
                "start_time": "2023-10-05T15:57:51.350841Z",
                "end_time": "2023-10-05T15:57:51.547472Z",
                "runtime_configuration": {},
                "config": "TestVisualizer",
                "type": "visualizer",
                "report": [
                  {
                    "level": 1,
                    "elements": {
                        "type": "horizontal_list",
                        "values": []
                    }
                  }
                ]
              },
              {
                "id": 731,
                "name": "Test page 2",
                "process_time": 0.0,
                "status": "SUCCESS",
                "errors": [],
                "start_time": "2023-10-05T15:57:51.350841Z",
                "end_time": "2023-10-05T15:57:51.547472Z",
                "runtime_configuration": {},
                "config": "TestVisualizer",
                "type": "visualizer",
                "report": [
                  {
                    "level": 1,
                    "elements": {
                        "type": "horizontal_list",
                        "values": []
                    }
                  }
                ]
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
    const secondPageReport = screen.getByText("Test page 2");
    expect(secondPageReport).toBeInTheDocument();
    // check active subsection
    expect(firstPageReport.closest("a").className).toContain("active");
    expect(secondPageReport.closest("a").className).not.toContain("active");
    
    await user.click(secondPageReport)
    expect(global.location.pathname).toEqual("/jobs/108/visualizer/Test%20page%202");
  })

  test("move from visualizer-Test page 1 to raw-analyzer", async() => {
    render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          section="visualizer"
          subSection="Test page 1"
          refetch={() => {}}
          job={{
            id: 108,
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
                "id": 730,
                "name": "Test page 1",
                "process_time": 0.0,
                "status": "SUCCESS",
                "errors": [],
                "start_time": "2023-10-05T15:57:51.350841Z",
                "end_time": "2023-10-05T15:57:51.547472Z",
                "runtime_configuration": {},
                "config": "TestVisualizer",
                "type": "visualizer",
                "report": [
                  {
                    "level": 1,
                    "elements": {
                        "type": "horizontal_list",
                        "values": []
                    }
                  }
                ]
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
    
    await user.click(rawButton)
    expect(global.location.pathname).toEqual("/jobs/108/raw/analyzer");
  })

  test("move from raw-analyzer to raw-connector", async() => {
    render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          section="raw"
          subSection="analyzer"
          refetch={() => {}}
          job={{
            id: 108,
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
    // check active subsection
    expect(analyzerReport.closest("a").className).toContain("active");
    expect(connectorReport.closest("a").className).not.toContain("active");
    expect(pivotReport.closest("a").className).not.toContain("active");
    expect(visualizerReport.closest("a").className).not.toContain("active");
    
    await user.click(connectorReport)
    expect(global.location.pathname).toEqual("/jobs/108/raw/connector");
  })

  test("move from raw-analyzer to raw-pivot", async() => {
    render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          section="raw"
          subSection="analyzer"
          refetch={() => {}}
          job={{
            id: 108,
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
    // check active subsection
    expect(analyzerReport.closest("a").className).toContain("active");
    expect(connectorReport.closest("a").className).not.toContain("active");
    expect(pivotReport.closest("a").className).not.toContain("active");
    expect(visualizerReport.closest("a").className).not.toContain("active");
    
    await user.click(pivotReport)
    expect(global.location.pathname).toEqual("/jobs/108/raw/pivot");
  })

  test("move from raw-analyzer to raw-visualizer", async() => {
    render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          section="raw"
          subSection="analyzer"
          refetch={() => {}}
          job={{
            id: 108,
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
    // check active subsection
    expect(analyzerReport.closest("a").className).toContain("active");
    expect(connectorReport.closest("a").className).not.toContain("active");
    expect(pivotReport.closest("a").className).not.toContain("active");
    expect(visualizerReport.closest("a").className).not.toContain("active");
    
    await user.click(visualizerReport)
    expect(global.location.pathname).toEqual("/jobs/108/raw/visualizer");
  })

  test("move from raw-visualizer to raw-analyzer", async() => {
    render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          section="raw"
          subSection="visualizer"
          refetch={() => {}}
          job={{
            id: 108,
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
    // check active subsection
    expect(analyzerReport.closest("a").className).not.toContain("active");
    expect(connectorReport.closest("a").className).not.toContain("active");
    expect(pivotReport.closest("a").className).not.toContain("active");
    expect(visualizerReport.closest("a").className).toContain("active");
    
    await user.click(analyzerReport)
    expect(global.location.pathname).toEqual("/jobs/108/raw/analyzer");
  })

  test("auto redirect - no visualizer", async() => {
    render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          section=""
          subSection=""
          refetch={() => {}}
          job={{
            id: 108,
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

    await waitFor(() => {
      expect(global.location.pathname).toEqual("/jobs/108/visualizer/no-visualizer");
    })
  })

  test("auto redirect - visualizer loading", async() => {
    render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          section=""
          subSection=""
          refetch={() => {}}
          job={{
            id: 108,
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
                "id": 730,
                "name": "Test page 1",
                "process_time": 0.0,
                "status": "running",
                "errors": [],
                "start_time": "2023-10-05T15:57:51.350841Z",
                "end_time": "2023-10-05T15:57:51.547472Z",
                "runtime_configuration": {},
                "config": "TestVisualizer",
                "type": "visualizer",
                "report": []
              }
            ],
            playbook_requested: "TestPlaybook",
            playbook_to_execute: "TestPlaybook",          
          }}
        />
      </BrowserRouter>,
    );

    await waitFor(() => {
      expect(global.location.pathname).toEqual("/jobs/108/visualizer/loading");
    })
  })

  test("auto redirect - visualizer reported", async() => {
    render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          section=""
          subSection=""
          refetch={() => {}}
          job={{
            id: 108,
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
                "id": 730,
                "name": "Test page 1",
                "process_time": 0.0,
                "status": "SUCCESS",
                "errors": [],
                "start_time": "2023-10-05T15:57:51.350841Z",
                "end_time": "2023-10-05T15:57:51.547472Z",
                "runtime_configuration": {},
                "config": "TestVisualizer",
                "type": "visualizer",
                "report": [
                  {
                    "level": 1,
                    "elements": {
                        "type": "horizontal_list",
                        "values": []
                    }
                  }
                ]
              }
            ],
            playbook_requested: "TestPlaybook",
            playbook_to_execute: "TestPlaybook",          
          }}
        />
      </BrowserRouter>,
    );

    await waitFor(() => {
      expect(global.location.pathname).toEqual("/jobs/108/visualizer/Test%20page%201");
    })
  })

});
