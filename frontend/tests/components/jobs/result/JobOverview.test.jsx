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
// mock useNavigate
const mockedUsedNavigate = jest.fn();
jest.mock("react-router-dom", () => ({
  ...jest.requireActual("react-router-dom"),
  useNavigate: () => mockedUsedNavigate,
}));

describe("test JobOverview (job report)", () => {
  let jobReport;
  beforeEach(() => {
    jobReport = {
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
      investigation: null,
      investigation_id: null,
      investigation_name: null,
      analyzable_id: 1,
    };
  });

  test("JobOverview components", () => {
    const { container } = render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          section="raw"
          subSection="analyzer"
          refetch={() => {}}
          job={jobReport}
          relatedInvestigationNumber={10}
        />
      </BrowserRouter>,
    );

    // Page title
    expect(screen.getByRole("heading", { name: "Job #1" })).toBeInTheDocument();
    // status
    expect(
      container.querySelector("#statusicon-reported_without_fails"),
    ).toBeInTheDocument();
    // actions bar
    const utilitiesRow = container.querySelector("#utilitiesRow");
    expect(within(utilitiesRow).getByText("Job #1")).toBeInTheDocument();
    const actionMenuButton = container.querySelector("#jobActions");
    expect(actionMenuButton).toBeInTheDocument();
    expect(
      within(utilitiesRow).getByRole("button", { name: "Comments" }),
    ).toBeInTheDocument();
    expect(within(utilitiesRow).getByText("Artifact")).toBeInTheDocument();
    // info card
    const JobInfoCardSection = container.querySelector("#JobInfoCardSection");
    expect(JobInfoCardSection).toBeInTheDocument();

    // investigation buttons ->  once we know the JobInfoCard Component is load the check about them are in the proper file

    // name
    expect(
      screen.getByRole("heading", { name: "dns.google.com" }),
    ).toBeInTheDocument();
    expect(screen.getByText("domain")).toBeInTheDocument();
    // dropdown button
    const JobInfoCardDropDownButton = container.querySelector(
      "#JobInfoCardDropDown",
    );
    expect(JobInfoCardDropDownButton).toBeInTheDocument();
  });

  test.each([
    // from analyzers to connectors
    {
      subSectionButtonName: "Connectors Report",
      path: "/jobs/1/raw/connector",
    },
    // from analyzers to pivots
    {
      subSectionButtonName: "Pivots Report",
      path: "/jobs/1/raw/pivot",
    },
    // from analyzers to visualizers
    {
      subSectionButtonName: "Visualizers Report",
      path: "/jobs/1/raw/visualizer",
    },
    // from analyzers to full report
    {
      subSectionButtonName: "Full Report",
      path: "/jobs/1/raw/full",
    },
    // from analyzers to data model
    {
      subSectionButtonName: "Data Model",
      path: "/jobs/1/raw/data_model",
    },
    // from analyzers to Visualizer tab
    {
      subSectionButtonName: "Visualizer",
      path: "/jobs/1/visualizer/Test_page_1",
    },
  ])(
    "Raw sections - from Analyzers Report to $subSectionButtonName",
    async ({ subSectionButtonName, path }) => {
      render(
        <BrowserRouter>
          <JobOverview
            isRunningJob={false}
            section="raw"
            subSection="analyzer"
            refetch={() => {}}
            job={jobReport}
          />
        </BrowserRouter>,
      );
      const user = userEvent.setup();

      // check sections visualizer/raw
      const visualizerButton = screen.getByRole("button", {
        name: "Visualizer",
      });
      expect(visualizerButton).toBeInTheDocument();
      expect(visualizerButton.className).toContain("btn-outline-tertiary"); // not selected
      const rawButton = screen.getByRole("button", { name: "Raw" });
      expect(rawButton).toBeInTheDocument();
      expect(rawButton.className).toContain("btn-secondary"); // selected
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
      const dataModel = screen.getByText("Data Model");
      expect(dataModel).toBeInTheDocument();
      // check active subsection
      expect(analyzerReport.closest("a").className).toContain("active");
      expect(connectorReport.closest("a").className).not.toContain("active");
      expect(pivotReport.closest("a").className).not.toContain("active");
      expect(visualizerReport.closest("a").className).not.toContain("active");
      expect(fullReport.closest("a").className).not.toContain("active");
      expect(dataModel.closest("a").className).not.toContain("active");

      await user.click(screen.getByText(subSectionButtonName));
      await expect(mockedUsedNavigate).toHaveBeenCalledTimes(1);
      await expect(mockedUsedNavigate).toHaveBeenCalledWith(path, {
        state: { userChanged: true, jobReport },
      });
    },
  );

  test("Move from Raw section to Visualizer section - no visualizer", async () => {
    // edit job report
    jobReport.visualizers_requested = [];
    jobReport.visualizers_to_execute = [];
    jobReport.visualizer_reports = [];

    render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          section="raw"
          subSection="analyzer"
          refetch={() => {}}
          job={jobReport}
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
    expect(rawButton.className).toContain("btn-secondary"); // selected
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
    const dataModel = screen.getByText("Data Model");
    expect(dataModel).toBeInTheDocument();
    // check active subsection
    expect(analyzerReport.closest("a").className).toContain("active");
    expect(connectorReport.closest("a").className).not.toContain("active");
    expect(pivotReport.closest("a").className).not.toContain("active");
    expect(visualizerReport.closest("a").className).not.toContain("active");
    expect(fullReport.closest("a").className).not.toContain("active");
    expect(dataModel.closest("a").className).not.toContain("active");

    await user.click(visualizerButton);
    await expect(mockedUsedNavigate).toHaveBeenCalledTimes(1);
    await expect(mockedUsedNavigate).toHaveBeenCalledWith(
      "/jobs/1/visualizer/no-visualizer",
      { state: { userChanged: true, jobReport } },
    );
  });

  test("Move from Visualizer section to Raw section", async () => {
    render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          section="visualizer"
          subSection="Test_page_1"
          refetch={() => {}}
          job={jobReport}
        />
      </BrowserRouter>,
    );
    const user = userEvent.setup();

    // check sections visualizer/raw
    const visualizerButton = screen.getByRole("button", { name: "Visualizer" });
    expect(visualizerButton).toBeInTheDocument();
    expect(visualizerButton.className).toContain("btn-secondary"); // selected
    const rawButton = screen.getByRole("button", { name: "Raw" });
    expect(rawButton).toBeInTheDocument();
    expect(rawButton.className).toContain("btn-outline-tertiary"); // not selected
    // check subsections available
    const firstPageReport = screen.getByText("Test_page_1");
    expect(firstPageReport).toBeInTheDocument();
    // check active subsection
    expect(firstPageReport.closest("a").className).toContain("active");

    await user.click(rawButton);
    await expect(mockedUsedNavigate).toHaveBeenCalledTimes(1);
    await expect(mockedUsedNavigate).toHaveBeenCalledWith(
      "/jobs/1/raw/analyzer",
      { state: { userChanged: true, jobReport } },
    );
  });

  test("Move from Visualizer (page 1/2) to Visualizer (page 2/2)", async () => {
    // edit job report
    jobReport.visualizer_reports = [
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
      {
        id: 731,
        name: "Test_page_2",
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
    ];

    render(
      <BrowserRouter>
        <JobOverview
          isRunningJob={false}
          section="visualizer"
          subSection="Test_page_1"
          refetch={() => {}}
          job={jobReport}
        />
      </BrowserRouter>,
    );
    const user = userEvent.setup();

    // check sections visualizer/raw
    const visualizerButton = screen.getByRole("button", { name: "Visualizer" });
    expect(visualizerButton).toBeInTheDocument();
    expect(visualizerButton.className).toContain("btn-secondary"); // selected
    const rawButton = screen.getByRole("button", { name: "Raw" });
    expect(rawButton).toBeInTheDocument();
    expect(rawButton.className).toContain("btn-outline-tertiary"); // not selected
    // check subsections available
    const firstPageReport = screen.getByText("Test_page_1");
    expect(firstPageReport).toBeInTheDocument();
    const secondPageReport = screen.getByText("Test_page_2");
    expect(secondPageReport).toBeInTheDocument();
    // check active subsection
    expect(firstPageReport.closest("a").className).toContain("active");
    expect(secondPageReport.closest("a").className).not.toContain("active");

    await user.click(secondPageReport);
    await expect(mockedUsedNavigate).toHaveBeenCalledTimes(1);
    await expect(mockedUsedNavigate).toHaveBeenCalledWith(
      "/jobs/1/visualizer/Test_page_2",
      { state: { userChanged: true, jobReport } },
    );
  });
});
