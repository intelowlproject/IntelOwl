import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import axios from "axios";
import ScanForm from "../../../../src/components/scan/ScanForm";

import {
  mockedUseAuthStore,
  mockedUseTagsStore,
  mockedUsePluginConfigurationStore,
} from "../../../mock";
import {
  ANALYZE_MULTIPLE_OBSERVABLE_URI,
  PLAYBOOKS_ANALYZE_MULTIPLE_OBSERVABLE_URI,
} from "../../../../src/constants/apiURLs";

jest.mock("axios");
// IMPORTANT: this mocks work with several storages because all of them are imported from index!
jest.mock("../../../../src/stores/useAuthStore", () => ({
  useAuthStore: jest.fn((state) => state(mockedUseAuthStore)),
}));
jest.mock("../../../../src/stores/useTagsStore", () => ({
  useTagsStore: jest.fn((state) => state(mockedUseTagsStore)),
}));
jest.mock("../../../../src/stores/usePluginConfigurationStore", () => ({
  usePluginConfigurationStore: jest.fn((state) =>
    state(mockedUsePluginConfigurationStore),
  ),
}));
// mock RecentScans component
jest.mock("../../../../src/components/scan/utils/RecentScans", () =>
  jest.fn((props) => <div {...props} />),
);

describe("ScanForm adavanced use", () => {
  /* EXTREMELY IMPORTART! These tests need to be execute sequentially or they will fail!
    Maintain them in the same describe
    */

  beforeAll(() => {
    axios.post.mockImplementation(() =>
      Promise.resolve({
        data: {
          results: [
            {
              job_id: 1,
              analyzers_running: [],
              connectors_running: [],
              visualizers_running: [],
              playbook_running: "TEST_PLAYBOOK_GENERIC",
              status: "accepted",
            },
          ],
          count: 1,
        },
      }),
    );
  });

  test("toast new job with playbook", async () => {
    axios.post.mockImplementation(() =>
      Promise.resolve({
        data: {
          results: [
            {
              job_id: 1,
              analyzers_running: [],
              connectors_running: [],
              visualizers_running: [],
              playbook_running: "TEST_PLAYBOOK_GENERIC",
              status: "accepted",
              already_exists: false,
            },
          ],
          count: 1,
        },
      }),
    );
    const user = userEvent.setup();
    render(
      <BrowserRouter>
        <ScanForm />
      </BrowserRouter>,
    );

    const firstObservableInputElement = screen.getByRole("textbox", {
      name: "",
    });
    await user.type(firstObservableInputElement, "newObservable");
    // check playbooks has been loaded
    expect(screen.getByText("TEST_PLAYBOOK_GENERIC")).toBeInTheDocument();
    // check scan is enabled
    const startScanButton = screen.getByRole("button", {
      name: "Start Scan",
    });
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).not.toContain("disabled");

    await user.click(startScanButton);
    await waitFor(() => {
      expect(axios.post.mock.calls).toEqual([
        [
          PLAYBOOKS_ANALYZE_MULTIPLE_OBSERVABLE_URI,
          {
            observables: [["generic", "newObservable"]],
            playbook_requested: "TEST_PLAYBOOK_GENERIC",
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
      ]);
    });

    /* without the setTimeout the expect doesn't work, but this timeout isn't real:
            it doesn't wait 15 or the test will go on timeout.
            This setTimeout makes other test fails (related to parallel execution)
        */
    // setTimeout(() => {
    //     expect(screen.getByText("Created new Job with ID(s) #1")).toBeInTheDocument();
    // }, 15 * 1000);
  });

  test("toast existing job with playbook", async () => {
    axios.post.mockImplementation(() =>
      Promise.resolve({
        data: {
          results: [
            {
              job_id: 2,
              analyzers_running: [],
              connectors_running: [],
              visualizers_running: [],
              playbook_running: "TEST_PLAYBOOK_GENERIC",
              status: "accepted",
              already_exists: true,
            },
          ],
          count: 1,
        },
      }),
    );
    const user = userEvent.setup();
    render(
      <BrowserRouter>
        <ScanForm />
      </BrowserRouter>,
    );

    const firstObservableInputElement = screen.getByRole("textbox", {
      name: "",
    });
    await user.type(
      firstObservableInputElement,
      "previouslyAnalyzerObservable",
    );
    // check playbooks has been loaded
    expect(screen.getByText("TEST_PLAYBOOK_GENERIC")).toBeInTheDocument();
    // check scan is enabled
    const startScanButton = screen.getByRole("button", {
      name: "Start Scan",
    });
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).not.toContain("disabled");

    await user.click(startScanButton);
    await waitFor(() => {
      expect(axios.post.mock.calls).toEqual([
        [
          PLAYBOOKS_ANALYZE_MULTIPLE_OBSERVABLE_URI,
          {
            observables: [["generic", "previouslyAnalyzerObservable"]],
            playbook_requested: "TEST_PLAYBOOK_GENERIC",
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
      ]);
    });

    /* without the setTimeout the expect doesn't work, but this timeout isn't real:
        it doesn't wait 15 or the test will go on timeout.
        This setTimeout makes other test fails (related to parallel execution)
    */
    // setTimeout(() => {
    //     expect(
    //     screen.getByText("Reported existing Job with ID(s) #2"),
    //     ).toBeInTheDocument();
    // }, 15 * 1000);
  });

  test("toasts both new and existing jobs with playbook", async () => {
    axios.post.mockImplementation(() =>
      Promise.resolve({
        data: {
          results: [
            {
              job_id: 1,
              analyzers_running: [],
              connectors_running: [],
              visualizers_running: [],
              playbook_running: "TEST_PLAYBOOK_GENERIC",
              status: "accepted",
              already_exists: false,
            },
            {
              job_id: 2,
              analyzers_running: [],
              connectors_running: [],
              visualizers_running: [],
              playbook_running: "TEST_PLAYBOOK_GENERIC",
              status: "accepted",
              already_exists: true,
            },
          ],
          count: 2,
        },
      }),
    );
    const user = userEvent.setup();
    render(
      <BrowserRouter>
        <ScanForm />
      </BrowserRouter>,
    );

    const firstObservableInputElement = screen.getByRole("textbox", {
      name: "",
    });
    await user.type(firstObservableInputElement, "newObservable");
    // add value
    const addObservableButton = screen.getByText("Add new value");
    expect(addObservableButton).toBeInTheDocument();
    await user.click(addObservableButton);
    // add second observable
    const secondObservableInputElement = screen.getAllByRole("textbox", {
      name: "",
    })[1];
    await user.type(
      secondObservableInputElement,
      "previouslyAnalyzerObservable",
    );
    // check playbooks has been loaded
    expect(screen.getByText("TEST_PLAYBOOK_GENERIC")).toBeInTheDocument();
    // check scan is enabled
    const startScanButton = screen.getByRole("button", {
      name: "Start Scan",
    });
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).not.toContain("disabled");

    await user.click(startScanButton);
    await waitFor(() => {
      expect(axios.post.mock.calls).toEqual([
        [
          PLAYBOOKS_ANALYZE_MULTIPLE_OBSERVABLE_URI,
          {
            observables: [
              ["generic", "newObservable"],
              ["generic", "previouslyAnalyzerObservable"],
            ],
            playbook_requested: "TEST_PLAYBOOK_GENERIC",
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
      ]);
    });

    /* without the setTimeout the expect doesn't work, but this timeout isn't real:
        it doesn't wait 15 or the test will go on timeout.
        This setTimeout makes other test fails (related to parallel execution)
    */
    // setTimeout(() => {
    //     expect(
    //     screen.getByText("Created new Job with ID(s) #1"),
    //     ).toBeInTheDocument();
    //     expect(
    //     screen.getByText("Reported existing Job with ID(s) #2"),
    //     ).toBeInTheDocument();
    // }, 15 * 1000);
  });

  test("toast new job without playbook", async () => {
    axios.post.mockImplementation(() =>
      Promise.resolve({
        data: {
          results: [
            {
              job_id: 1,
              analyzers_running: ["TEST_ANALYZER"],
              connectors_running: [],
              visualizers_running: [],
              playbook_running: null,
              status: "accepted",
              already_exists: false,
            },
          ],
          count: 1,
        },
      }),
    );
    const user = userEvent.setup();
    const { container } = render(
      <BrowserRouter>
        <ScanForm />
      </BrowserRouter>,
    );

    const firstObservableInputElement = screen.getByRole("textbox", {
      name: "",
    });
    await user.type(firstObservableInputElement, "newObservable");
    const analyzerSelectionRadioButton = screen.getAllByRole("radio")[3];
    expect(analyzerSelectionRadioButton).toBeInTheDocument();
    await user.click(analyzerSelectionRadioButton);
    expect(screen.getByText("Select Analyzers")).toBeInTheDocument();
    expect(screen.getByText("Select Connectors")).toBeInTheDocument();

    /* the id change in case you run a single test or all of them.
        we need this strange way to access instead of the id */
    const analyzerDropdownButton = screen.getAllByRole("combobox")[0];
    expect(analyzerDropdownButton).toBeInTheDocument();
    await user.click(analyzerDropdownButton);
    const testAnalyzerButton = container.querySelector(
      `#${analyzerDropdownButton.id.replace("-input", "")}-option-0`,
    );
    expect(testAnalyzerButton).toBeInTheDocument();
    await user.click(testAnalyzerButton);
    expect(screen.getByText("TEST_ANALYZER")).toBeInTheDocument();
    // check scan is enabled
    const startScanButton = screen.getByRole("button", {
      name: "Start Scan",
    });
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).not.toContain("disabled");

    await user.click(startScanButton);
    await waitFor(() => {
      expect(axios.post.mock.calls).toEqual([
        [
          ANALYZE_MULTIPLE_OBSERVABLE_URI,
          {
            observables: [["generic", "newObservable"]],
            tlp: "AMBER",
            scan_mode: 2,
            analyzers_requested: ["TEST_ANALYZER"],
            scan_check_time: "24:00:00",
          },
          { headers: { "Content-Type": "application/json" } },
        ],
      ]);
    });

    /* without the setTimeout the expect doesn't work, but this timeout isn't real:
        it doesn't wait 15 or the test will go on timeout.
        This setTimeout makes other test fails (related to parallel execution)
    */
    // setTimeout(() => {
    //     expect(
    //     screen.getByText("Created new Job with ID(s) #1"),
    //     ).toBeInTheDocument();
    // }, 15 * 1000);
  });

  test("toast existing job without playbook", async () => {
    axios.post.mockImplementation(() =>
      Promise.resolve({
        data: {
          results: [
            {
              job_id: 2,
              analyzers_running: ["TEST_ANALYZER"],
              connectors_running: [],
              visualizers_running: [],
              playbook_running: null,
              status: "accepted",
              already_exists: true,
            },
          ],
          count: 1,
        },
      }),
    );
    const user = userEvent.setup();
    const { container } = render(
      <BrowserRouter>
        <ScanForm />
      </BrowserRouter>,
    );

    const firstObservableInputElement = screen.getByRole("textbox", {
      name: "",
    });
    await user.type(
      firstObservableInputElement,
      "previouslyAnalyzerObservable",
    );
    const analyzerSelectionRadioButton = screen.getAllByRole("radio")[3];
    expect(analyzerSelectionRadioButton).toBeInTheDocument();
    await user.click(analyzerSelectionRadioButton);

    expect(screen.getByText("Select Analyzers")).toBeInTheDocument();
    expect(screen.getByText("Select Connectors")).toBeInTheDocument();
    const analyzerDropdownButton = screen.getAllByRole("combobox")[0];
    expect(analyzerDropdownButton).toBeInTheDocument();
    await user.click(analyzerDropdownButton);

    /* the id change in case you run a single test or all of them.
        we need this strange way to access instead of the id */
    const testAnalyzerButton = container.querySelector(
      `#${analyzerDropdownButton.id.replace("-input", "")}-option-0`,
    );
    expect(testAnalyzerButton).toBeInTheDocument();
    await user.click(testAnalyzerButton);

    expect(screen.getByText("TEST_ANALYZER")).toBeInTheDocument();
    // check scan is enabled
    const startScanButton = screen.getByRole("button", {
      name: "Start Scan",
    });
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).not.toContain("disabled");

    await user.click(startScanButton);

    await waitFor(() => {
      expect(axios.post.mock.calls).toEqual([
        [
          ANALYZE_MULTIPLE_OBSERVABLE_URI,
          {
            observables: [["generic", "previouslyAnalyzerObservable"]],
            tlp: "AMBER",
            scan_mode: 2,
            analyzers_requested: ["TEST_ANALYZER"],
            scan_check_time: "24:00:00",
          },
          { headers: { "Content-Type": "application/json" } },
        ],
      ]);
    });

    /* without the setTimeout the expect doesn't work, but this timeout isn't real:
        it doesn't wait 15 or the test will go on timeout.
        This setTimeout makes other test fails (related to parallel execution)
    */
    // setTimeout(() => {
    //     expect(
    //     screen.getByText("Reported existing Job with ID(s) #2"),
    //     ).toBeInTheDocument();
    // }, 15 * 1000);
  });

  test("toasts both new and existing jobs without playbook", async () => {
    axios.post.mockImplementation(() =>
      Promise.resolve({
        data: {
          results: [
            {
              job_id: 1,
              analyzers_running: ["TEST_ANALYZER"],
              connectors_running: [],
              visualizers_running: [],
              playbook_running: null,
              status: "accepted",
              already_exists: false,
            },
            {
              job_id: 2,
              analyzers_running: ["TEST_ANALYZER"],
              connectors_running: [],
              visualizers_running: [],
              playbook_running: null,
              status: "accepted",
              already_exists: true,
            },
          ],
          count: 2,
        },
      }),
    );
    const user = userEvent.setup();
    const { container } = render(
      <BrowserRouter>
        <ScanForm />
      </BrowserRouter>,
    );

    const firstObservableInputElement = screen.getByRole("textbox", {
      name: "",
    });
    await user.type(firstObservableInputElement, "newObservable");
    // add value
    const addObservableButton = screen.getByText("Add new value");
    expect(addObservableButton).toBeInTheDocument();
    await user.click(addObservableButton);

    const secondObservableInputElement = screen.getAllByRole("textbox", {
      name: "",
    })[1];
    await user.type(
      secondObservableInputElement,
      "previouslyAnalyzerObservable",
    );

    // add second observable
    const analyzerSelectionRadioButton = screen.getAllByRole("radio")[3];
    expect(analyzerSelectionRadioButton).toBeInTheDocument();
    await user.click(analyzerSelectionRadioButton);

    expect(screen.getByText("Select Analyzers")).toBeInTheDocument();
    expect(screen.getByText("Select Connectors")).toBeInTheDocument();
    /* the id change in case you run a single test or all of them.
        we need this strange way to access instead of the id */
    const analyzerDropdownButton = screen.getAllByRole("combobox")[0];
    expect(analyzerDropdownButton).toBeInTheDocument();
    await user.click(analyzerDropdownButton);

    const testAnalyzerButton = container.querySelector(
      `#${analyzerDropdownButton.id.replace("-input", "")}-option-0`,
    );
    expect(testAnalyzerButton).toBeInTheDocument();
    await user.click(testAnalyzerButton);

    expect(screen.getByText("TEST_ANALYZER")).toBeInTheDocument();
    // check scan is enabled
    const startScanButton = screen.getByRole("button", {
      name: "Start Scan",
    });
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).not.toContain("disabled");

    await user.click(startScanButton);
    await waitFor(() => {
      expect(axios.post.mock.calls).toEqual([
        [
          ANALYZE_MULTIPLE_OBSERVABLE_URI,
          {
            observables: [
              ["generic", "newObservable"],
              ["generic", "previouslyAnalyzerObservable"],
            ],
            tlp: "AMBER",
            scan_mode: 2,
            analyzers_requested: ["TEST_ANALYZER"],
            scan_check_time: "24:00:00",
          },
          { headers: { "Content-Type": "application/json" } },
        ],
      ]);
    });

    /* without the setTimeout the expect doesn't work, but this timeout isn't real:
        it doesn't wait 15 or the test will go on timeout.
        This setTimeout makes other test fails (related to parallel execution)
    */
    // setTimeout(() => {
    //     expect(
    //     screen.getByText("Created new Job with ID(s) #1"),
    //     ).toBeInTheDocument();
    //     expect(
    //     screen.getByText("Reported existing Job with ID(s) #2"),
    //     ).toBeInTheDocument();
    // }, 15 * 1000);
  });
});
