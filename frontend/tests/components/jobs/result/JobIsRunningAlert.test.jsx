/* eslint-disable id-length */
import React from "react";
import axios from "axios";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import { JobIsRunningAlert } from "../../../../src/components/jobs/result/JobIsRunningAlert";
import { JOB_BASE_URI } from "../../../../src/constants/apiURLs";

jest.mock("reactflow/dist/style.css", () => {});
jest.mock("axios");

describe("test JobIsRunningAlert", () => {
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

  test("JobIsRunningAlert - analyzers running", () => {
    const { container } = render(
      <BrowserRouter>
        <JobIsRunningAlert
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
            status: "analyzers_running",
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
            analyzers_to_execute: ["Classic_DNS"],
            analyzer_reports: [
              {
                id: 174,
                name: "Classic_DNS",
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
            connectors_requested: ["MISP"],
            connectors_to_execute: ["MISP"],
            connector_reports: [
              {
                id: 175,
                name: "MISP",
                process_time: 0.07,
                report: {},
                status: "RUNNING",
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
                status: "RUNNING",
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
                status: "RUNNING",
                errors: [],
                start_time: "2023-05-31T08:19:03.380434Z",
                end_time: "2023-05-31T08:19:03.455218Z",
                runtime_configuration: {},
                config: "DNS",
                type: "visualizer",
              },
            ],
            playbook_requested: null,
            playbook_to_execute: null,
          }}
        />
      </BrowserRouter>,
    );

    const JobPipelineFlow = container.querySelector("#JobPipelineFlow");
    expect(JobPipelineFlow).toBeInTheDocument();
    // analyzers node
    const analyzersNode = container.querySelector("#jobPipeline-step-1");
    expect(analyzersNode).toBeInTheDocument();
    expect(analyzersNode.textContent).toContain("ANALYZERS RUNNING");
    expect(analyzersNode.textContent).toContain("Reported 0/1");
    // connectors node
    const connectorsNode = container.querySelector("#jobPipeline-step-2");
    expect(connectorsNode).toBeInTheDocument();
    expect(connectorsNode.textContent).toContain("CONNECTORS");
    expect(connectorsNode.textContent).toContain("Reported 0/1");
    // pivots node
    const pivotsNode = container.querySelector("#jobPipeline-step-3");
    expect(pivotsNode).toBeInTheDocument();
    expect(pivotsNode.textContent).toContain("PIVOTS");
    expect(pivotsNode.textContent).toContain("Reported 0/1");
    // visualizers node
    const visualizersNode = container.querySelector("#jobPipeline-step-4");
    expect(visualizersNode).toBeInTheDocument();
    expect(visualizersNode.textContent).toContain("VISUALIZERS");
    expect(visualizersNode.textContent).toContain("Reported 0/1");
  });

  test("JobIsRunningAlert - connectors running", () => {
    const { container } = render(
      <BrowserRouter>
        <JobIsRunningAlert
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
            status: "connectors_running",
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
                status: "RUNNING",
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
                status: "RUNNING",
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
                status: "RUNNING",
                errors: [],
                start_time: "2023-05-31T08:19:03.380434Z",
                end_time: "2023-05-31T08:19:03.455218Z",
                runtime_configuration: {},
                config: "DNS",
                type: "visualizer",
              },
            ],
            playbook_requested: null,
            playbook_to_execute: null,
          }}
        />
      </BrowserRouter>,
    );

    const JobPipelineFlow = container.querySelector("#JobPipelineFlow");
    expect(JobPipelineFlow).toBeInTheDocument();
    // analyzers node
    const analyzersNode = container.querySelector("#jobPipeline-step-1");
    expect(analyzersNode).toBeInTheDocument();
    expect(analyzersNode.textContent).toContain("ANALYZERS COMPLETED");
    expect(analyzersNode.textContent).toContain("Reported 1/1");
    // connectors node
    const connectorsNode = container.querySelector("#jobPipeline-step-2");
    expect(connectorsNode).toBeInTheDocument();
    expect(connectorsNode.textContent).toContain("CONNECTORS RUNNING");
    expect(connectorsNode.textContent).toContain("Reported 0/1");
    // pivots node
    const pivotsNode = container.querySelector("#jobPipeline-step-3");
    expect(pivotsNode).toBeInTheDocument();
    expect(pivotsNode.textContent).toContain("PIVOTS");
    expect(pivotsNode.textContent).toContain("Reported 0/1");
    // visualizers node
    const visualizersNode = container.querySelector("#jobPipeline-step-4");
    expect(visualizersNode).toBeInTheDocument();
    expect(visualizersNode.textContent).toContain("VISUALIZERS");
    expect(visualizersNode.textContent).toContain("Reported 0/1");
  });

  test("JobIsRunningAlert - pivots running", () => {
    const { container } = render(
      <BrowserRouter>
        <JobIsRunningAlert
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
            status: "pivots_running",
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
                status: "RUNNING",
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
                status: "RUNNING",
                errors: [],
                start_time: "2023-05-31T08:19:03.380434Z",
                end_time: "2023-05-31T08:19:03.455218Z",
                runtime_configuration: {},
                config: "DNS",
                type: "visualizer",
              },
            ],
            playbook_requested: null,
            playbook_to_execute: null,
          }}
        />
      </BrowserRouter>,
    );

    const JobPipelineFlow = container.querySelector("#JobPipelineFlow");
    expect(JobPipelineFlow).toBeInTheDocument();
    // analyzers node
    const analyzersNode = container.querySelector("#jobPipeline-step-1");
    expect(analyzersNode).toBeInTheDocument();
    expect(analyzersNode.textContent).toContain("ANALYZERS COMPLETED");
    expect(analyzersNode.textContent).toContain("Reported 1/1");
    // connectors node
    const connectorsNode = container.querySelector("#jobPipeline-step-2");
    expect(connectorsNode).toBeInTheDocument();
    expect(connectorsNode.textContent).toContain("CONNECTORS COMPLETED");
    expect(connectorsNode.textContent).toContain("Reported 1/1");
    // pivots node
    const pivotsNode = container.querySelector("#jobPipeline-step-3");
    expect(pivotsNode).toBeInTheDocument();
    expect(pivotsNode.textContent).toContain("PIVOTS RUNNING");
    expect(pivotsNode.textContent).toContain("Reported 0/1");
    // visualizers node
    const visualizersNode = container.querySelector("#jobPipeline-step-4");
    expect(visualizersNode).toBeInTheDocument();
    expect(visualizersNode.textContent).toContain("VISUALIZERS");
    expect(visualizersNode.textContent).toContain("Reported 0/1");
  });

  test("JobIsRunningAlert - visualizers running", () => {
    const { container } = render(
      <BrowserRouter>
        <JobIsRunningAlert
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
            status: "visualizers_running",
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
                status: "RUNNING",
                errors: [],
                start_time: "2023-05-31T08:19:03.380434Z",
                end_time: "2023-05-31T08:19:03.455218Z",
                runtime_configuration: {},
                config: "DNS",
                type: "visualizer",
              },
            ],
            playbook_requested: null,
            playbook_to_execute: null,
          }}
        />
      </BrowserRouter>,
    );

    const JobPipelineFlow = container.querySelector("#JobPipelineFlow");
    expect(JobPipelineFlow).toBeInTheDocument();
    // analyzers node
    const analyzersNode = container.querySelector("#jobPipeline-step-1");
    expect(analyzersNode).toBeInTheDocument();
    expect(analyzersNode.textContent).toContain("ANALYZERS COMPLETED");
    expect(analyzersNode.textContent).toContain("Reported 1/1");
    // connectors node
    const connectorsNode = container.querySelector("#jobPipeline-step-2");
    expect(connectorsNode).toBeInTheDocument();
    expect(connectorsNode.textContent).toContain("CONNECTORS COMPLETED");
    expect(connectorsNode.textContent).toContain("Reported 1/1");
    // pivots node
    const pivotsNode = container.querySelector("#jobPipeline-step-3");
    expect(pivotsNode).toBeInTheDocument();
    expect(pivotsNode.textContent).toContain("PIVOTS COMPLETED");
    expect(pivotsNode.textContent).toContain("Reported 1/1");
    // visualizers node
    const visualizersNode = container.querySelector("#jobPipeline-step-4");
    expect(visualizersNode).toBeInTheDocument();
    expect(visualizersNode.textContent).toContain("VISUALIZERS RUNNING");
    expect(visualizersNode.textContent).toContain("Reported 0/1");
  });

  test("JobIsRunningAlert - kill job button", async () => {
    axios.patch.mockImplementation(() =>
      Promise.resolve({ status: 204, data: {} }),
    );

    const { container } = render(
      <BrowserRouter>
        <JobIsRunningAlert
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
            status: "visualizers_running",
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
                status: "RUNNING",
                errors: [],
                start_time: "2023-05-31T08:19:03.380434Z",
                end_time: "2023-05-31T08:19:03.455218Z",
                runtime_configuration: {},
                config: "DNS",
                type: "visualizer",
              },
            ],
            playbook_requested: null,
            playbook_to_execute: null,
          }}
        />
      </BrowserRouter>,
    );

    const user = userEvent.setup();

    const JobPipelineFlow = container.querySelector("#JobPipelineFlow");
    expect(JobPipelineFlow).toBeInTheDocument();
    // kill job button
    const killJobButton = container.querySelector("#killjob-iconbutton");
    expect(killJobButton).toBeInTheDocument();
    expect(killJobButton.textContent).toContain("Kill job");
    await user.click(killJobButton);
    // confirm dialog
    const confirmButton = screen.getByRole("button", {
      name: "Ok",
    });
    await user.click(confirmButton);
    await waitFor(() => {
      expect(axios.patch.mock.calls.length).toBe(1);
      expect(axios.patch).toHaveBeenCalledWith(`${JOB_BASE_URI}/1/kill`);
    });
  });
});
