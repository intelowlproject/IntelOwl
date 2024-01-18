import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import axios from "axios";
import userEvent from "@testing-library/user-event";
import ScanForm from "../../../../../src/components/scan/ScanForm";
import { sanitizeObservable } from "../../../../../src/utils/observables";
import {
  ANALYZE_MULTIPLE_OBSERVABLE_URI,
  PLAYBOOKS_ANALYZE_MULTIPLE_OBSERVABLE_URI,
} from "../../../../../src/constants/apiURLs";
import { ScanModesNumeric } from "../../../../../src/constants/advancedSettingsConst";
import { parseScanCheckTime } from "../../../../../src/utils/time";
import RecentScans from "../../../../../src/components/scan/utils/RecentScans";

import {
  mockedUseAuthStore,
  mockedUseTagsStore,
  mockedUsePluginConfigurationStore,
  mockedPlaybooks,
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

describe("test ScanForm component with domains", () => {
  test.each([
    {
      type: "domain",
      firstObservable: "google.com",
      secondObservable: "microsoft[[.]]com",
      playbook: mockedPlaybooks.TEST_PLAYBOOK_DOMAIN,
    },
    {
      type: "generic",
      firstObservable: "genericText",
      secondObservable: "genericText2",
      playbook: mockedPlaybooks.TEST_PLAYBOOK_GENERIC,
    },
    {
      type: "hash",
      firstObservable: "1d5920f4b44b27a802bd77c4f0536f5a",
      secondObservable: "ff5c054c7cd6924c570f944007ccf076",
      playbook: mockedPlaybooks.TEST_PLAYBOOK_HASH,
    },
    {
      type: "ip",
      firstObservable: "8.8.8.8",
      secondObservable: "1[[.]]1[[.]]1[[.]]1",
      playbook: mockedPlaybooks.TEST_PLAYBOOK_IP,
    },
    {
      type: "url",
      firstObservable: "https://google.com",
      secondObservable: "https://microsoft[[.]]com",
      playbook: mockedPlaybooks.TEST_PLAYBOOK_URL,
    },
  ])(
    "playbook analysis (%s)",
    async ({ type, firstObservable, secondObservable, playbook }) => {
      const user = userEvent.setup();

      axios.post.mockReturnValueOnce({
        data: {
          results: [
            {
              job_id: 1,
              analyzers_running: [],
              connectors_running: [],
              visualizers_running: [],
              playbook_running: playbook.name,
              status: "accepted",
            },
          ],
          count: 1,
        },
      });

      render(
        <BrowserRouter>
          <ScanForm />
        </BrowserRouter>,
      );

      const firstObservableInputElement = screen.getByRole("textbox", {
        name: "",
      });
      await user.type(firstObservableInputElement, firstObservable);
      // recent scans
      await waitFor(() => {
        expect(RecentScans).toHaveBeenCalledWith(
          { classification: type, param: firstObservable },
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
      await user.type(secondObservableInputElement, secondObservable);

      // check playbooks has been loaded
      expect(screen.getByText(playbook.name)).toBeInTheDocument();
      // check scan is enabled
      const startScanButton = screen.getByRole("button", {
        name: "Start Scan",
      });
      expect(startScanButton).toBeInTheDocument();
      expect(startScanButton.className).not.toContain("disabled");

      const payload = {
        observables: [
          [type, firstObservable],
          [type, sanitizeObservable(secondObservable)],
        ],
        playbook_requested: playbook.name,
        tlp: playbook.tlp,
        scan_mode: playbook.scan_mode,
        runtime_configuration: playbook.runtime_configuration,
      };

      if (
        playbook.scan_mode ===
        parseInt(ScanModesNumeric.CHECK_PREVIOUS_ANALYSIS, 10)
      ) {
        payload.scan_check_time = `${parseScanCheckTime(
          playbook.scan_check_time,
        )}:00:00`;
      }

      if (playbook.tags.length) {
        payload.tags_labels = [playbook.tags[0].label];
      }

      const axiosCall = [
        [
          PLAYBOOKS_ANALYZE_MULTIPLE_OBSERVABLE_URI,
          payload,
          { headers: { "Content-Type": "application/json" } },
        ],
      ];

      await user.click(startScanButton);
      await waitFor(() => {
        expect(axios.post.mock.calls).toEqual(axiosCall);
      });
    },
  );

  test.each([
    {
      type: "domain",
      firstObservable: "google.com",
      secondObservable: "microsoft[[.]]com",
    },
    {
      type: "generic",
      firstObservable: "genericText",
      secondObservable: "genericText2",
    },
    {
      type: "hash",
      firstObservable: "1d5920f4b44b27a802bd77c4f0536f5a",
      secondObservable: "ff5c054c7cd6924c570f944007ccf076",
    },
    {
      type: "ip",
      firstObservable: "8.8.8.8",
      secondObservable: "1[[.]]1[[.]]1[[.]]1",
    },
    {
      type: "url",
      firstObservable: "https://google.com",
      secondObservable: "https://microsoft[[.]]com",
    },
  ])(
    "analyzer analysis (%s)",
    async ({ type, firstObservable, secondObservable }) => {
      const user = userEvent.setup();

      axios.post.mockReturnValueOnce({
        data: {
          results: [
            {
              job_id: 1,
              analyzers_running: [],
              connectors_running: [],
              visualizers_running: [],
              status: "accepted",
            },
          ],
          count: 1,
        },
      });

      const { container } = render(
        <BrowserRouter>
          <ScanForm />
        </BrowserRouter>,
      );

      const firstObservableInputElement = screen.getByRole("textbox", {
        name: "",
      });
      await user.type(firstObservableInputElement, firstObservable);
      // recent scans
      await waitFor(() => {
        expect(RecentScans).toHaveBeenCalledWith(
          { classification: type, param: firstObservable },
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
      await user.type(secondObservableInputElement, secondObservable);

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
                [type, firstObservable],
                [type, sanitizeObservable(secondObservable)],
              ],
              analyzers_requested: ["TEST_ANALYZER"],
              tlp: "AMBER",
              scan_mode: 2,
              scan_check_time: "24:00:00",
            },
            { headers: { "Content-Type": "application/json" } },
          ],
        ]);
      });
    },
  );
});
