/* eslint-disable id-length */
import React from "react";
import "@testing-library/jest-dom";
import { render, within } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import { JobInfoCard } from "../../../../src/components/jobs/result/JobInfoCard";

jest.mock("reactflow/dist/style.css", () => {});

describe("test JobInfoCard (job report)", () => {
  // mock needed for testing flow https://reactflow.dev/learn/advanced-use/testing#using-jest
  beforeEach(() => {
    let MockObserverInstance = typeof ResizeObserver;
    MockObserverInstance = {
      observe: jest.fn(),
      unobserve: jest.fn(),
      disconnect: jest.fn(),
    };
    global.ResizeObserver = jest
      .fn()
      .mockImplementation(() => MockObserverInstance);

    let MockDOMMatrixInstance = typeof DOMMatrixReadOnly;
    const mockDOMMatrix = (transform) => {
      const scale = transform?.match(/scale\(([1-9.])\)/)?.[1];
      MockDOMMatrixInstance = {
        m22: scale !== undefined ? +scale : 1,
      };
      return MockDOMMatrixInstance;
    };
    global.DOMMatrixReadOnly = jest
      .fn()
      .mockImplementation((transform) => mockDOMMatrix(transform));

    Object.defineProperties(global.HTMLElement.prototype, {
      offsetHeight: {
        get() {
          return parseFloat(this.style.height) || 1;
        },
      },
      offsetWidth: {
        get() {
          return parseFloat(this.style.width) || 1;
        },
      },
    });

    global.SVGElement.prototype.getBBox = () => ({
      x: 0,
      y: 0,
      width: 0,
      height: 0,
    });
  });

  test("metadata section", () => {
    const { container } = render(
      <BrowserRouter>
        <JobInfoCard
          job={{
            id: 1,
            user: {
              username: "test",
            },
            tags: [],
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
            status: "reported_without_fails",
            runtime_configuration: {
              analyzers: {},
              connectors: {},
              pivots: {},
              visualizers: {},
            },
            received_request_time: "2023-05-31T08:19:03.256003",
            finished_analysis_time: "2023-05-31T08:19:04.484684",
            investigation: 1,
            investigation_id: 1,
            investigation_name: "test investigation",
            analyzable_id: 1,
            process_time: 0.23,
            tlp: "AMBER",
            warnings: [],
            errors: [],
            analyzers_requested: ["Classic_DNS"],
            analyzers_to_execute: ["Classic_DNS"],
            analyzer_reports: [
              {
                id: 174,
                name: "Classic_DNS",
                process_time: 0.07,
                report: {},
                status: "SUCCESS",
                errors: [],
                start_time: "2023-05-31T08:19:03.380434Z",
                end_time: "2023-05-31T08:19:03.455218Z",
                runtime_configuration: {},
                type: "analyzer",
              },
            ],
            connectors_requested: ["MISP"],
            connectors_to_execute: ["MISP"],
            connector_reports: [
              {
                id: 175,
                name: "MISP",
                process_time: 0.07,
                report: {},
                status: "SUCCESS",
                errors: [],
                start_time: "2023-05-31T08:19:03.380434Z",
                end_time: "2023-05-31T08:19:03.455218Z",
                runtime_configuration: {},
                type: "connector",
              },
            ],
            pivots_requested: ["Pivot1"],
            pivots_to_execute: ["Pivot1"],
            pivot_reports: [
              {
                id: 176,
                name: "Pivot1",
                process_time: 0.07,
                report: {},
                status: "SUCCESS",
                errors: [],
                start_time: "2023-05-31T08:19:03.380434Z",
                end_time: "2023-05-31T08:19:03.455218Z",
                runtime_configuration: {},
                type: "pivot",
              },
            ],
            visualizers_requested: ["DNS"],
            visualizers_to_execute: ["DNS"],
            visualizer_reports: [
              {
                id: 177,
                name: "DNS",
                process_time: 0.07,
                report: {},
                status: "SUCCESS",
                errors: [],
                start_time: "2023-05-31T08:19:03.380434Z",
                end_time: "2023-05-31T08:19:03.455218Z",
                runtime_configuration: {},
                config: "DNS",
                type: "visualizer",
              },
            ],
            playbook_requested: "TestPlaybook",
            playbook_to_execute: "TestPlaybook",
          }}
        />
      </BrowserRouter>,
    );

    // always visible line
    const JobInfoCardSection = container.querySelector("#JobInfoCardSection");
    expect(
      within(JobInfoCardSection).getByText("dns.google.com"),
    ).toBeInTheDocument();
    const JobInfoCardDropDownButton = container.querySelector(
      "#JobInfoCardDropDown",
    );
    expect(JobInfoCardDropDownButton).toBeInTheDocument();
    // metadata - first line
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
    expect(within(JobInfoCardSection).getByText("None")).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("Warning(s)"),
    ).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("0 warnings"),
    ).toBeInTheDocument();
    const JobWarningsDropDownButton = container.querySelector(
      "#JobWarningsDropDown",
    );
    expect(JobWarningsDropDownButton).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("Error(s)"),
    ).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("0 errors"),
    ).toBeInTheDocument();
    const JobErrorsDropDownButton =
      container.querySelector("#JobErrorsDropDown");
    expect(JobErrorsDropDownButton).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("Playbook"),
    ).toBeInTheDocument();
    expect(
      within(JobInfoCardSection).getByText("TestPlaybook"),
    ).toBeInTheDocument();

    // Job pipeline flow
    const JobPipelineFlow = container.querySelector("#JobPipelineFlow");
    expect(JobPipelineFlow).toBeInTheDocument();
  });
});
