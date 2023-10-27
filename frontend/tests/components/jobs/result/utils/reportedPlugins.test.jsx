import axios from "axios";
import "@testing-library/jest-dom";
import { reportedVisualizerNumber } from "../../../../../src/components/jobs/result/utils/reportedPlugins";

jest.mock("axios");
describe("test JobActionsBar", () => {
  beforeAll(() => {
    axios.post.mockImplementation(() =>
      Promise.resolve({ data: { results: [], count: 0 } }),
    );
  });

  test("reportedVisualizerNumber function - 2 visualizers (1 completed and 1 running)", async () => {
    const visualizersReportedList = [
      {
        id: 1,
        name: "DNS1",
        process_time: 0,
        report: [],
        status: "SUCCESS",
        errors: [],
        start_time: "2023-10-04T07:51:31.448024Z",
        end_time: "2023-10-04T07:51:31.448030Z",
        runtime_configuration: {},
        config: "DNS",
        type: "visualizer",
      },
      {
        id: 2,
        name: "IP1",
        process_time: 0,
        report: [],
        status: "FAILED",
        errors: [],
        start_time: "2023-10-04T07:51:31.448024Z",
        end_time: "2023-10-04T07:51:31.448030Z",
        runtime_configuration: {},
        config: "IP",
        type: "visualizer",
      },
      {
        id: 3,
        name: "IP2",
        process_time: 0,
        report: [],
        status: "SUCCESS",
        errors: [],
        start_time: "2023-10-04T07:51:31.448024Z",
        end_time: "2023-10-04T07:51:31.448030Z",
        runtime_configuration: {},
        config: "IP",
        type: "visualizer",
      },
      {
        id: 4,
        name: "IP3",
        process_time: 0,
        report: [],
        status: "RUNNING",
        errors: [],
        start_time: "2023-10-04T07:51:31.448024Z",
        end_time: "2023-10-04T07:51:31.448030Z",
        runtime_configuration: {},
        config: "IP",
        type: "visualizer",
      },
    ];
    const visualizersToExecute = ["DNS", "IP"];
    const result = reportedVisualizerNumber(
      visualizersReportedList,
      visualizersToExecute,
    );
    expect(result).toBe(1);
  });

  test("reportedVisualizerNumber function - all visualizers in running", async () => {
    const visualizersReportedList = [
      {
        id: 1,
        name: "DNS1",
        process_time: 0,
        report: [],
        status: "RUNNING",
        errors: [],
        start_time: "2023-10-04T07:51:31.448024Z",
        end_time: "2023-10-04T07:51:31.448030Z",
        runtime_configuration: {},
        config: "DNS",
        type: "visualizer",
      },
      {
        id: 2,
        name: "IP1",
        process_time: 0,
        report: [],
        status: "RUNNING",
        errors: [],
        start_time: "2023-10-04T07:51:31.448024Z",
        end_time: "2023-10-04T07:51:31.448030Z",
        runtime_configuration: {},
        config: "IP",
        type: "visualizer",
      },
    ];
    const visualizersToExecute = ["DNS", "IP"];
    const result = reportedVisualizerNumber(
      visualizersReportedList,
      visualizersToExecute,
    );
    expect(result).toBe(0);
  });

  test("reportedVisualizerNumber function - all visualizers reported", async () => {
    const visualizersReportedList = [
      {
        id: 1,
        name: "DNS1",
        process_time: 0,
        report: [],
        status: "FAILED",
        errors: [],
        start_time: "2023-10-04T07:51:31.448024Z",
        end_time: "2023-10-04T07:51:31.448030Z",
        runtime_configuration: {},
        config: "DNS",
        type: "visualizer",
      },
      {
        id: 2,
        name: "IP1",
        process_time: 0,
        report: [],
        status: "SUCCESS",
        errors: [],
        start_time: "2023-10-04T07:51:31.448024Z",
        end_time: "2023-10-04T07:51:31.448030Z",
        runtime_configuration: {},
        config: "IP",
        type: "visualizer",
      },
    ];
    const visualizersToExecute = ["DNS", "IP"];
    const result = reportedVisualizerNumber(
      visualizersReportedList,
      visualizersToExecute,
    );
    expect(result).toBe(2);
  });
});
