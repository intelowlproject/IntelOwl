import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import axios from "axios";
import userEvent from "@testing-library/user-event";
import ScanForm from "../../../../../src/components/scan/ScanForm";
import {
  ANALYZE_MULTIPLE_FILES_URI,
  PLAYBOOKS_ANALYZE_MULTIPLE_FILES_URI,
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

describe("test ScanForm component with files", () => {
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

  test("file playbook analysis", async () => {
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <ScanForm />
      </BrowserRouter>,
    );

    // select file type
    const fileSelectorRadioButton = screen.getAllByRole("radio")[1];
    expect(fileSelectorRadioButton).toBeInTheDocument();
    await user.click(fileSelectorRadioButton);
    expect(screen.getByText("File(s)")).toBeInTheDocument();

    // select file
    // This mock is required because even if the files are uploaded they are empty (not found a solution)
    // and when the md5 is computed it raise an error, with this mock this problem is solved
    File.prototype.text = jest
      .fn()
      .mockResolvedValueOnce("this is a text line")
      .mockResolvedValueOnce("this is another line");
    const fileInputComponent = screen.getByLabelText("File(s)");
    const testImageFiles = [
      new File(["this is a text line"], "test1.txt", { type: "plain/text" }),
      new File(["this is another line"], "test2.txt", { type: "plain/text" }),
    ];
    await user.upload(fileInputComponent, testImageFiles);
    expect(fileInputComponent.files).toHaveLength(2);
    expect(fileInputComponent.files[0]).toStrictEqual(testImageFiles[0]);
    expect(fileInputComponent.files.item(0)).toStrictEqual(testImageFiles[0]);
    expect(fileInputComponent.files[1]).toStrictEqual(testImageFiles[1]);
    expect(fileInputComponent.files.item(1)).toStrictEqual(testImageFiles[1]);

    // check playbooks has been loaded
    expect(screen.getByText("TEST_PLAYBOOK_FILE")).toBeInTheDocument();
    // check scan is enabled
    const startScanButton = screen.getByRole("button", { name: "Start Scan" });
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).not.toContain("disabled");

    // recent scans
    expect(RecentScans).toHaveBeenCalledWith(
      { classification: "file", param: testImageFiles[0] },
      {},
    );

    await user.click(startScanButton);
    await waitFor(() => {
      expect(axios.post.mock.calls.length).toBe(1);
      // axios call: start new analysis
      expect(axios.post.mock.calls[0][0]).toEqual(
        PLAYBOOKS_ANALYZE_MULTIPLE_FILES_URI,
      );
      expect(Object.fromEntries(axios.post.mock.calls[0][1])).toEqual({
        files: new File([], ""),
        playbook_requested: "TEST_PLAYBOOK_FILE",
        runtime_configuration: JSON.stringify({
          analyzers: {},
          connectors: {},
          visualizers: {},
        }),
        tlp: "AMBER",
        scan_mode: "1",
      });
      expect(axios.post.mock.calls[0][2]).toEqual({
        headers: { "Content-Type": "multipart/form-data" },
      });
    });
  });

  test("file analyzer analysis", async () => {
    const user = userEvent.setup();

    const { container } = render(
      <BrowserRouter>
        <ScanForm />
      </BrowserRouter>,
    );

    // select file type
    const fileSelectorRadioButton = screen.getAllByRole("radio")[1];
    expect(fileSelectorRadioButton).toBeInTheDocument();
    await user.click(fileSelectorRadioButton);
    expect(screen.getByText("File(s)")).toBeInTheDocument();

    // select analyzer
    const analyzerSelectionRadioButton = screen.getAllByRole("radio")[3];
    expect(analyzerSelectionRadioButton).toBeInTheDocument();
    await user.click(analyzerSelectionRadioButton);
    expect(screen.getByText("Select Analyzers")).toBeInTheDocument();
    expect(screen.getByText("Select Connectors")).toBeInTheDocument();

    // select file
    // This mock is required because even if the files are uploaded they are empty (not found a solution)
    // and when the md5 is computed it raise an error, with this mock this problem is solved
    File.prototype.text = jest
      .fn()
      .mockResolvedValueOnce("this is a text line")
      .mockResolvedValueOnce("this is another line");
    const fileInputComponent = screen.getByLabelText("File(s)");
    const testImageFiles = [
      new File(["this is a text line"], "test1.txt", { type: "plain/text" }),
      new File(["this is another line"], "test2.txt", { type: "plain/text" }),
    ];
    await user.upload(fileInputComponent, testImageFiles);
    expect(fileInputComponent.files).toHaveLength(2);
    expect(fileInputComponent.files[0]).toStrictEqual(testImageFiles[0]);
    expect(fileInputComponent.files.item(0)).toStrictEqual(testImageFiles[0]);
    expect(fileInputComponent.files[1]).toStrictEqual(testImageFiles[1]);
    expect(fileInputComponent.files.item(1)).toStrictEqual(testImageFiles[1]);

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

    // recent scans
    expect(RecentScans).toHaveBeenCalledWith(
      { classification: "file", param: testImageFiles[0] },
      {},
    );

    await user.click(startScanButton);
    await waitFor(() => {
      expect(axios.post.mock.calls.length).toBe(1);
      // axios call: start new analysis
      expect(axios.post.mock.calls[0][0]).toEqual(ANALYZE_MULTIPLE_FILES_URI);
      expect(Object.fromEntries(axios.post.mock.calls[0][1])).toEqual({
        analyzers_requested: "TEST_ANALYZER",
        files: new File([""], ""),
        tlp: "AMBER",
        scan_mode: "2",
        scan_check_time: "24:00:00",
      });
      expect(axios.post.mock.calls[0][2]).toEqual({
        headers: { "Content-Type": "multipart/form-data" },
      });
    });
  });
});
