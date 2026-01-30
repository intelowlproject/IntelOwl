import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import axios from "axios";
import ScanForm from "../../../../src/components/scan/ScanForm";
import Toast from "../../../../src/layouts/Toast";

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

describe("ScanForm advanced use", () => {
  beforeAll(() => {
    jest.setTimeout(30000);
  });
  /* EXTREMELY IMPORTART! These tests need to be execute sequentially or they will fail!
     Maintain them in the same describe.

     Note: each test has a different job_id because the toasts are saved and shown for 10 seconds, 
     so during the second test the first toast will still be shown.
  */
  test.each([
    // toast new job with playbook
    {
      responseData: [
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
      jobCount: 1,
    },
    // toast existing job with playbook
    {
      responseData: [
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
      jobCount: 1,
    },
    // toasts both new and existing jobs with playbook
    {
      responseData: [
        {
          job_id: 3,
          analyzers_running: [],
          connectors_running: [],
          visualizers_running: [],
          playbook_running: "TEST_PLAYBOOK_GENERIC",
          status: "accepted",
          already_exists: false,
        },
        {
          job_id: 4,
          analyzers_running: [],
          connectors_running: [],
          visualizers_running: [],
          playbook_running: "TEST_PLAYBOOK_GENERIC",
          status: "accepted",
          already_exists: true,
        },
      ],
      jobCount: 2,
    },
  ])("toast with playbook (%s)", async ({ responseData, jobCount }) => {
    axios.post.mockImplementation(() =>
      Promise.resolve({
        data: {
          results: responseData,
          count: jobCount,
        },
      }),
    );

    const user = userEvent.setup();
    render(
      <BrowserRouter>
        <ScanForm />
        <Toast />
      </BrowserRouter>,
    );

    const firstObservableInputElement = screen.getByRole("textbox", {
      name: "",
    });
    await user.type(firstObservableInputElement, "newObservable");
    // check playbooks has been loaded
    expect(screen.getAllByText("TEST_PLAYBOOK_GENERIC")[0]).toBeInTheDocument();
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
    if (jobCount === 1) {
      if (responseData.already_exists) {
        expect(
          screen.getByText("Reported existing Job with ID(s) #2!"),
        ).toBeInTheDocument();
      } else {
        expect(
          screen.getByText("Created new Job with ID(s) #1!"),
        ).toBeInTheDocument();
      }
    } else {
      expect(
        screen.getByText("Created new Job with ID(s) #3!"),
      ).toBeInTheDocument();
      expect(
        screen.getByText("Reported existing Job with ID(s) #4!"),
      ).toBeInTheDocument();
    }
  });

  test.each([
    // toast new job without playbook
    {
      responseData: [
        {
          job_id: 5,
          analyzers_running: ["TEST_ANALYZER"],
          connectors_running: [],
          visualizers_running: [],
          playbook_running: null,
          status: "accepted",
          already_exists: false,
        },
      ],
      jobCount: 1,
    },
    // toast existing job without playbook
    {
      responseData: [
        {
          job_id: 6,
          analyzers_running: ["TEST_ANALYZER"],
          connectors_running: [],
          visualizers_running: [],
          playbook_running: null,
          status: "accepted",
          already_exists: true,
        },
      ],
      jobCount: 1,
    },
    // toasts both new and existing jobs without playbook
    {
      responseData: [
        {
          job_id: 7,
          analyzers_running: ["TEST_ANALYZER"],
          connectors_running: [],
          visualizers_running: [],
          playbook_running: null,
          status: "accepted",
          already_exists: false,
        },
        {
          job_id: 8,
          analyzers_running: ["TEST_ANALYZER"],
          connectors_running: [],
          visualizers_running: [],
          playbook_running: null,
          status: "accepted",
          already_exists: true,
        },
      ],
      jobCount: 2,
    },
  ])("toast without playbook (%s)", async ({ responseData, jobCount }) => {
    const user = userEvent.setup();
    axios.post.mockImplementation(() =>
      Promise.resolve({
        data: {
          results: responseData,
          count: jobCount,
        },
      }),
    );

    render(
      <BrowserRouter>
        <ScanForm />
        <Toast />
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
    const testAnalyzerButton = document.querySelector(
      `#${analyzerDropdownButton.id.replace("-input", "")}-option-0`,
    );
    expect(testAnalyzerButton).toBeInTheDocument();
    await user.click(testAnalyzerButton);
    expect(screen.getAllByText("TEST_ANALYZER")[0]).toBeInTheDocument();
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
    if (jobCount === 1) {
      if (responseData.already_exists) {
        expect(
          screen.getByText("Reported existing Job with ID(s) #6!"),
        ).toBeInTheDocument();
      } else {
        expect(
          screen.getByText("Created new Job with ID(s) #5!"),
        ).toBeInTheDocument();
      }
    } else {
      expect(
        screen.getByText("Created new Job with ID(s) #7!"),
      ).toBeInTheDocument();
      expect(
        screen.getByText("Reported existing Job with ID(s) #8!"),
      ).toBeInTheDocument();
    }
  });
});
