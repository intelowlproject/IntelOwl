import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import axios from "axios";
import userEvent from "@testing-library/user-event";
import ScanForm from "../../../../../src/components/scan/ScanForm";
import {
  ANALYZE_MULTIPLE_OBSERVABLE_URI,
  PLAYBOOKS_ANALYZE_MULTIPLE_OBSERVABLE_URI,
} from "../../../../../src/constants/apiURLs";
import RecentScans from "../../../../../src/components/scan/utils/RecentScans";

import {
  mockedUseAuthStore,
  mockedUseTagsStore,
  mockedUsePluginConfigurationStore,
} from "../../../../mock";

jest.mock("axios");
// IMPORTANT: this mocks work with several storages because all of them are imported from index!
jest.mock("../../../../../src/stores/useAuthStore", () => ({
  useAuthStore: jest.fn((state) => state(mockedUseAuthStore)),
}));
jest.mock("../../../../../src/stores/useTagsStore", () => ({
  useTagsStore: jest.fn((state) => state(mockedUseTagsStore)),
}));
jest.mock("../../../../../src/stores/usePluginConfigurationStore", () => ({
  usePluginConfigurationStore: jest.fn((state) =>
    state(mockedUsePluginConfigurationStore),
  ),
}));
// mock RecentScans component
jest.mock("../../../../../src/components/scan/utils/RecentScans", () =>
  jest.fn((props) => <div {...props} />),
);

describe("test ScanForm component with generics", () => {
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

  test("generic playbook analysis", async () => {
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <ScanForm />
      </BrowserRouter>,
    );

    const firstObservableInputElement = screen.getByRole("textbox", {
      name: "",
    });
    await user.type(firstObservableInputElement, "genericText");
    // recent scans
    await waitFor(() => {
      expect(RecentScans).toHaveBeenCalledWith(
        { classification: "generic", param: "genericText" },
        {},
      );
    });
    // add second observable to analyze
    const addNewValueButton = screen.getByRole("button", {
      name: "Add new value",
    });
    expect(addNewValueButton).toBeInTheDocument();
    await user.click(addNewValueButton);
    const secondObservableInputElement = screen.getAllByRole("textbox", {
      name: "",
    })[1];
    // doubled braked are required by user-event library
    await user.type(secondObservableInputElement, "genericText2");
    // recent scans
    await waitFor(() => {
      expect(RecentScans).toHaveBeenCalledWith(
        { classification: "generic", param: "genericText2" },
        {},
      );
    });

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
        // axios call: start new analysis
        [
          PLAYBOOKS_ANALYZE_MULTIPLE_OBSERVABLE_URI,
          {
            observables: [
              ["generic", "genericText"],
              ["generic", "genericText2"],
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
      // check redirect to job page
      expect(global.location.pathname).toContain("/jobs/1/visualizer/");
    });
  });

  test("generic analyzer analysis", async () => {
    const user = userEvent.setup();

    const { container } = render(
      <BrowserRouter>
        <ScanForm />
      </BrowserRouter>,
    );

    const firstObservableInputElement = screen.getByRole("textbox", {
      name: "",
    });
    await user.type(firstObservableInputElement, "genericText");
    // recent scans
    await waitFor(() => {
      expect(RecentScans).toHaveBeenCalledWith(
        { classification: "generic", param: "genericText" },
        {},
      );
    });
    // add second observable to analyze
    const addNewValueButton = screen.getByRole("button", {
      name: "Add new value",
    });
    expect(addNewValueButton).toBeInTheDocument();
    await user.click(addNewValueButton);
    const secondObservableInputElement = screen.getAllByRole("textbox", {
      name: "",
    })[1];
    // doubled braked are required by user-event library
    await user.type(secondObservableInputElement, "genericText2");
    // recent scans
    await waitFor(() => {
      expect(RecentScans).toHaveBeenCalledWith(
        { classification: "generic", param: "genericText2" },
        {},
      );
    });

    // select analyzer
    const analyzerSelectionRadioButton = screen.getAllByRole("radio")[3];
    expect(analyzerSelectionRadioButton).toBeInTheDocument();
    await user.click(analyzerSelectionRadioButton);
    expect(screen.getByText("Select Analyzers")).toBeInTheDocument();
    expect(screen.getByText("Select Connectors")).toBeInTheDocument();

    // select the test analyzer
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

    // recent scans
    expect(RecentScans).toHaveBeenCalledWith(
      { classification: "generic", param: "genericText" },
      {},
    );

    // check scan is enabled
    const startScanButton = screen.getByRole("button", {
      name: "Start Scan",
    });
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).not.toContain("disabled");

    await user.click(startScanButton);
    await waitFor(() => {
      expect(axios.post.mock.calls).toEqual([
        // axios call: start new analysis
        [
          ANALYZE_MULTIPLE_OBSERVABLE_URI,
          {
            observables: [
              ["generic", "genericText"],
              ["generic", "genericText2"],
            ],
            analyzers_requested: ["TEST_ANALYZER"],
            tlp: "AMBER",
            scan_mode: 2,
            scan_check_time: "24:00:00",
          },
          { headers: { "Content-Type": "application/json" } },
        ],
      ]);
      // check redirect to job page
      expect(global.location.pathname).toContain("/jobs/1/visualizer/");
    });
  });
});
