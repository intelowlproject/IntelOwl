import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Routes, Route, BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import axios from "axios";
import ScanForm from "../../../../src/components/scan/ScanForm";

import {
  mockedUseAuthStore,
  mockedUseTagsStore,
  mockedUsePluginConfigurationStore,
} from "../../../mock";
import RecentScans from "../../../../src/components/scan/utils/RecentScans";
import {
  ANALYZE_MULTIPLE_FILES_URI,
  ANALYZE_MULTIPLE_OBSERVABLE_URI,
  PLAYBOOKS_ANALYZE_MULTIPLE_FILES_URI,
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

  test("test scan page with an observable in the GET parameters", async () => {
    render(
      <MemoryRouter
        initialEntries={["/scan?observable=thisIsTheParamObservable.com"]}
      >
        <Routes>
          <Route path="/scan" element={<ScanForm />} />
        </Routes>
      </MemoryRouter>,
    );

    // check value has been loaded
    expect(screen.getAllByRole("textbox")[0].value).toBe(
      "thisIsTheParamObservable.com",
    );
    // check playbooks has been loaded
    expect(screen.getByText("TEST_PLAYBOOK_DOMAIN")).toBeInTheDocument();
  });

  test("test scan page with sample in the GET parameters", async () => {
    render(
      <MemoryRouter initialEntries={["/scan?isSample=true"]}>
        <Routes>
          <Route path="/scan" element={<ScanForm />} />
        </Routes>
      </MemoryRouter>,
    );

    // check file radio button is selected and input file rendered
    const fileSelectorRadioButton = screen.getAllByRole("radio")[1];
    expect(fileSelectorRadioButton).toBeInTheDocument();
    expect(fileSelectorRadioButton.checked).toBe(true);
    expect(screen.getByText("File(s)")).toBeInTheDocument();
  });

  test("test scan page with an investigation in the GET parameters", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter initialEntries={["/scan?investigation=1"]}>
        <Routes>
          <Route path="/scan" element={<ScanForm />} />
        </Routes>
      </MemoryRouter>,
    );

    // select an observable and start scan
    const firstObservableInputElement = screen.getByRole("textbox", {
      name: "",
    });
    await user.type(firstObservableInputElement, "google.com");

    // check playbooks has been loaded
    expect(screen.getByText("TEST_PLAYBOOK_DOMAIN")).toBeInTheDocument();

    // start scan button
    const startScanButton = screen.getByRole("button", {
      name: "Start Scan",
    });
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).not.toContain("disabled");

    await user.click(startScanButton);

    await waitFor(() => {
      expect(axios.post.mock.calls[0]).toEqual(
        // axios call
        [
          PLAYBOOKS_ANALYZE_MULTIPLE_OBSERVABLE_URI,
          {
            observables: [["domain", "google.com"]],
            playbook_requested: "TEST_PLAYBOOK_DOMAIN",
            tlp: "CLEAR",
            scan_mode: 2,
            scan_check_time: "48:00:00",
            runtime_configuration: {
              analyzers: {},
              connectors: {},
              visualizers: {},
            },
            investigation: "1",
          },
          { headers: { "Content-Type": "application/json" } },
        ],
      );
    });
  });

  test("test scan page with a parent and an observable in the GET parameters", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter
        initialEntries={[
          "/scan?parent=1&observable=thisIsTheParamObservable.com",
        ]}
      >
        <Routes>
          <Route path="/scan" element={<ScanForm />} />
        </Routes>
      </MemoryRouter>,
    );

    // check value has been loaded
    expect(screen.getAllByRole("textbox")[0].value).toBe(
      "thisIsTheParamObservable.com",
    );
    // check playbooks has been loaded
    expect(screen.getByText("TEST_PLAYBOOK_DOMAIN")).toBeInTheDocument();

    // start scan button
    const startScanButton = screen.getByRole("button", {
      name: "Start Scan",
    });
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).not.toContain("disabled");

    await user.click(startScanButton);

    await waitFor(() => {
      expect(axios.post.mock.calls[0]).toEqual(
        // axios call
        [
          PLAYBOOKS_ANALYZE_MULTIPLE_OBSERVABLE_URI,
          {
            observables: [["domain", "thisIsTheParamObservable.com"]],
            playbook_requested: "TEST_PLAYBOOK_DOMAIN",
            tlp: "CLEAR",
            scan_mode: 2,
            scan_check_time: "48:00:00",
            runtime_configuration: {
              analyzers: {},
              connectors: {},
              visualizers: {},
            },
            parent_job: "1",
          },
          { headers: { "Content-Type": "application/json" } },
        ],
      );
    });
  });

  test("test playbooks advanced change time", async () => {
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <ScanForm />
      </BrowserRouter>,
    );

    // select an observable and start scan
    const firstObservableInputElement = screen.getByRole("textbox", {
      name: "",
    });
    await user.type(firstObservableInputElement, "google.com");

    /* advanced settings:
          if you modify advanced settings before typing the observable when the playbook auto load override the advanced settings
          Don't move this block before the observable typing!!!
        */
    const advancedSettingsButton = screen.getByRole("button", {
      name: "Advanced settings",
    });
    await user.click(advancedSettingsButton);
    const timeRangeSelector = screen.getByRole("spinbutton");
    expect(timeRangeSelector).toBeInTheDocument();
    await user.clear(timeRangeSelector);
    await user.type(timeRangeSelector, "10");

    const startScanButton = screen.getByRole("button", {
      name: "Start Scan",
    });
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).not.toContain("disabled");
    // recent scans
    await waitFor(() => {
      expect(RecentScans).toHaveBeenCalledWith(
        { classification: "domain", param: "google.com" },
        {},
      );
    });
    await user.click(startScanButton);

    await waitFor(() => {
      expect(axios.post.mock.calls[0]).toEqual(
        // axios call
        [
          PLAYBOOKS_ANALYZE_MULTIPLE_OBSERVABLE_URI,
          {
            observables: [["domain", "google.com"]],
            playbook_requested: "TEST_PLAYBOOK_DOMAIN",
            tlp: "CLEAR",
            scan_mode: 2,
            scan_check_time: "10:00:00",
            runtime_configuration: {
              analyzers: {},
              connectors: {},
              visualizers: {},
            },
          },
          { headers: { "Content-Type": "application/json" } },
        ],
      );
    });
  });

  test("test analyzers advanced change time", async () => {
    const user = userEvent.setup();

    const { container } = render(
      <BrowserRouter>
        <ScanForm />
      </BrowserRouter>,
    );

    // select analyzer
    const analyzerSelectionRadioButton = screen.getAllByRole("radio")[3];
    expect(analyzerSelectionRadioButton).toBeInTheDocument();
    await user.click(analyzerSelectionRadioButton);
    // recent scans
    expect(RecentScans).toHaveBeenCalledWith(
      { classification: "generic", param: "" },
      {},
    );
    // select an observable
    const firstObservableInputElement = screen.getByRole("textbox", {
      name: "",
    });
    await user.type(firstObservableInputElement, "google.com");
    const startScanButton = screen.getByRole("button", {
      name: "Start Scan",
    });
    // recent scans
    await waitFor(() => {
      expect(RecentScans).toHaveBeenCalledWith(
        { classification: "domain", param: "google.com" },
        {},
      );
    });
    // advanced settings
    const advancedSettingsButton = screen.getByRole("button", {
      name: "Advanced settings",
    });
    await user.click(advancedSettingsButton);
    const timeRangeSelector = screen.getByRole("spinbutton");
    expect(timeRangeSelector).toBeInTheDocument();
    await user.clear(timeRangeSelector);
    await user.type(timeRangeSelector, "10");

    // select analyzer
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

    // start scan
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).not.toContain("disabled");
    await user.click(startScanButton);

    await waitFor(() => {
      expect(axios.post.mock.calls[0]).toEqual(
        // axios call
        [
          ANALYZE_MULTIPLE_OBSERVABLE_URI,
          {
            observables: [["domain", "google.com"]],
            analyzers_requested: ["TEST_ANALYZER"],
            tlp: "AMBER",
            scan_mode: 2,
            scan_check_time: "10:00:00",
          },
          { headers: { "Content-Type": "application/json" } },
        ],
      );
    });
  });

  test("test observable playbooks advanced settings (force analysis, tlp and tags)", async () => {
    const user = userEvent.setup();

    const { container } = render(
      <BrowserRouter>
        <ScanForm />
      </BrowserRouter>,
    );

    // select an observable
    const firstObservableInputElement = screen.getByRole("textbox", {
      name: "",
    });
    await user.type(firstObservableInputElement, "google.com");

    // advanced settings
    /* the id change in case you run a single test or all of them.
          we need this strange way to access instead of the id */
    const tagsDropdown = screen.getAllByRole("combobox")[1];
    expect(tagsDropdown).toBeInTheDocument();
    await user.click(tagsDropdown);
    const testTagButton = container.querySelector(
      `#${tagsDropdown.id.replace("-input", "")}-option-0`,
    );
    expect(testTagButton).toBeInTheDocument();
    await user.click(testTagButton);
    const advancedSettingsButton = screen.getByRole("button", {
      name: "Advanced settings",
    });
    await user.click(advancedSettingsButton);
    const tlpRadio = screen.getByRole("radio", { name: "GREEN" });
    expect(tlpRadio).toBeInTheDocument();
    await user.click(tlpRadio);
    const forceAnalysisRadio = screen.getByRole("radio", {
      name: "Force new analysis",
    });
    expect(forceAnalysisRadio).toBeInTheDocument();
    await user.click(forceAnalysisRadio);
    await waitFor(() => {
      expect(RecentScans).toHaveBeenCalledWith(
        { classification: "domain", param: "google.com" },
        {},
      );
    });
    // start scan
    const startScanButton = screen.getByRole("button", {
      name: "Start Scan",
    });
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).not.toContain("disabled");
    await user.click(startScanButton);

    await waitFor(() => {
      // no call to the API to check old analysis (one of the advanced settings)
      expect(axios.post.mock.calls.length).toBe(1);
      expect(axios.post.mock.calls).toEqual([
        [
          PLAYBOOKS_ANALYZE_MULTIPLE_OBSERVABLE_URI,
          {
            observables: [["domain", "google.com"]],
            playbook_requested: "TEST_PLAYBOOK_DOMAIN",
            tags_labels: ["test tag"],
            tlp: "GREEN",
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
  });

  test("test file playbooks advanced settings (force analysis, tlp and tags)", async () => {
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

    // select file
    const fileInputComponent = screen.getByLabelText("File(s)");
    const testImageFiles = [
      new File(["this is a text line"], "test1.txt", { type: "plain/text" }),
    ];
    await user.upload(fileInputComponent, testImageFiles);
    expect(fileInputComponent.files).toHaveLength(1);
    expect(fileInputComponent.files[0]).toStrictEqual(testImageFiles[0]);
    expect(fileInputComponent.files.item(0)).toStrictEqual(testImageFiles[0]);

    // advanced settings
    /* the id change in case you run a single test or all of them.
          we need this strange way to access instead of the id */
    const tagsDropdown = screen.getAllByRole("combobox")[1];
    expect(tagsDropdown).toBeInTheDocument();
    await user.click(tagsDropdown);
    const testTagButton = container.querySelector(
      `#${tagsDropdown.id.replace("-input", "")}-option-0`,
    );
    expect(testTagButton).toBeInTheDocument();
    await user.click(testTagButton);
    const advancedSettingsButton = screen.getByRole("button", {
      name: "Advanced settings",
    });
    await user.click(advancedSettingsButton);
    const tlpRadio = screen.getByRole("radio", { name: "GREEN" });
    expect(tlpRadio).toBeInTheDocument();
    await user.click(tlpRadio);
    const forceAnalysisRadio = screen.getByRole("radio", {
      name: "Force new analysis",
    });
    expect(forceAnalysisRadio).toBeInTheDocument();
    await user.click(forceAnalysisRadio);
    // recent scans
    expect(RecentScans).toHaveBeenCalledWith(
      { classification: "file", param: testImageFiles[0] },
      {},
    );

    // select an observable and start scan
    const startScanButton = screen.getByRole("button", {
      name: "Start Scan",
    });
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).not.toContain("disabled");
    await user.click(startScanButton);

    await waitFor(() => {
      // no call to the API to check old analysis (one of the advanced settings)
      expect(axios.post.mock.calls.length).toBe(1);
      expect(axios.post.mock.calls[0][0]).toEqual(
        PLAYBOOKS_ANALYZE_MULTIPLE_FILES_URI,
      );
      expect(Object.fromEntries(axios.post.mock.calls[0][1])).toEqual({
        files: new File([], ""),
        playbook_requested: "TEST_PLAYBOOK_FILE",
        tags_labels: "test tag",
        tlp: "GREEN",
        scan_mode: "1",
        runtime_configuration: JSON.stringify({
          analyzers: {},
          connectors: {},
          visualizers: {},
        }),
      });
      expect(axios.post.mock.calls[0][2]).toEqual({
        headers: { "Content-Type": "multipart/form-data" },
      });
    });
  });

  test("test observable analyzers advanced settings (force analysis, tlp and tags)", async () => {
    const user = userEvent.setup();

    const { container } = render(
      <BrowserRouter>
        <ScanForm />
      </BrowserRouter>,
    );

    // select an observable
    const firstObservableInputElement = screen.getByRole("textbox", {
      name: "",
    });
    await user.type(firstObservableInputElement, "google.com");
    // recent scans
    await waitFor(() => {
      expect(RecentScans).toHaveBeenCalledWith(
        { classification: "domain", param: "google.com" },
        {},
      );
    });
    // select analyzer
    const analyzerSelectionRadioButton = screen.getAllByRole("radio")[3];
    expect(analyzerSelectionRadioButton).toBeInTheDocument();
    await user.click(analyzerSelectionRadioButton);
    expect(screen.getByText("Select Analyzers")).toBeInTheDocument();
    expect(screen.getByText("Select Connectors")).toBeInTheDocument();

    // advanced settings
    /* the id change in case you run a single test or all of them.
          we need this strange way to access instead of the id */
    const tagsDropdown = screen.getAllByRole("combobox")[2];
    expect(tagsDropdown).toBeInTheDocument();
    await user.click(tagsDropdown);
    const testTagButton = container.querySelector(
      `#${tagsDropdown.id.replace("-input", "")}-option-0`,
    );
    expect(testTagButton).toBeInTheDocument();
    await user.click(testTagButton);
    const advancedSettingsButton = screen.getByRole("button", {
      name: "Advanced settings",
    });
    await user.click(advancedSettingsButton);
    const tlpRadio = screen.getByRole("radio", { name: "GREEN" });
    expect(tlpRadio).toBeInTheDocument();
    await user.click(tlpRadio);
    const forceAnalysisRadio = screen.getByRole("radio", {
      name: "Force new analysis",
    });
    expect(forceAnalysisRadio).toBeInTheDocument();
    await user.click(forceAnalysisRadio);

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

    const startScanButton = screen.getByRole("button", {
      name: "Start Scan",
    });
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).not.toContain("disabled");
    await user.click(startScanButton);

    await waitFor(() => {
      // no call to the API to check old analysis (one of the advanced settings)
      expect(axios.post.mock.calls.length).toBe(1);
      expect(axios.post.mock.calls).toEqual([
        [
          ANALYZE_MULTIPLE_OBSERVABLE_URI,
          {
            observables: [["domain", "google.com"]],
            analyzers_requested: ["TEST_ANALYZER"],
            tags_labels: ["test tag"],
            tlp: "GREEN",
            scan_mode: 1,
          },
          { headers: { "Content-Type": "application/json" } },
        ],
      ]);
    });
  });

  test("test file analyzers advanced settings (force analysis, tlp and tags)", async () => {
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

    // select file
    const fileInputComponent = screen.getByLabelText("File(s)");
    const testImageFiles = [
      new File(["this is a text line"], "test1.txt", { type: "plain/text" }),
    ];
    await user.upload(fileInputComponent, testImageFiles);
    expect(fileInputComponent.files).toHaveLength(1);
    expect(fileInputComponent.files[0]).toStrictEqual(testImageFiles[0]);
    expect(fileInputComponent.files.item(0)).toStrictEqual(testImageFiles[0]);

    // select analyzer
    const analyzerSelectionRadioButton = screen.getAllByRole("radio")[3];
    expect(analyzerSelectionRadioButton).toBeInTheDocument();
    await user.click(analyzerSelectionRadioButton);
    expect(screen.getByText("Select Analyzers")).toBeInTheDocument();
    expect(screen.getByText("Select Connectors")).toBeInTheDocument();

    // advanced settings
    const advancedSettingsButton = screen.getByRole("button", {
      name: "Advanced settings",
    });
    await user.click(advancedSettingsButton);
    /* the id change in case you run a single test or all of them.
          we need this strange way to access instead of the id */
    const tagsDropdown = screen.getAllByRole("combobox")[2];
    expect(tagsDropdown).toBeInTheDocument();
    await user.click(tagsDropdown);
    const testTagButton = container.querySelector(
      `#${tagsDropdown.id.replace("-input", "")}-option-0`,
    );
    expect(testTagButton).toBeInTheDocument();
    await user.click(testTagButton);
    const tlpRadio = screen.getByRole("radio", { name: "GREEN" });
    expect(tlpRadio).toBeInTheDocument();
    await user.click(tlpRadio);
    const forceAnalysisRadio = screen.getByRole("radio", {
      name: "Force new analysis",
    });
    expect(forceAnalysisRadio).toBeInTheDocument();
    await user.click(forceAnalysisRadio);

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
      { classification: "file", param: testImageFiles[0] },
      {},
    );

    const startScanButton = screen.getByRole("button", {
      name: "Start Scan",
    });
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).not.toContain("disabled");
    await user.click(startScanButton);

    await waitFor(() => {
      // force analysis avoid call for old analysis
      expect(axios.post.mock.calls.length).toBe(1);
      expect(axios.post.mock.calls[0][0]).toEqual(ANALYZE_MULTIPLE_FILES_URI);
      expect(Object.fromEntries(axios.post.mock.calls[0][1])).toEqual({
        analyzers_requested: "TEST_ANALYZER",
        files: new File([""], ""),
        tlp: "GREEN",
        tags_labels: "test tag",
        scan_mode: "1",
      });
      expect(axios.post.mock.calls[0][2]).toEqual({
        headers: { "Content-Type": "multipart/form-data" },
      });
    });
  });

  test("test add multiple observables", async () => {
    const user = userEvent.setup();

    const { container } = render(
      <BrowserRouter>
        <ScanForm />
      </BrowserRouter>,
    );

    // modal button
    const multipleObservablesButton = container.querySelector(
      `#scanform-multipleobservables-btn`,
    );
    expect(multipleObservablesButton).toBeInTheDocument();
    await user.click(multipleObservablesButton);
    // modal
    const modalInfo = screen.getByText(
      "Enter any text to extract observables for further lookup.",
    );
    expect(modalInfo).toBeInTheDocument();
    // editable text area
    const editableTextAreaSection = modalInfo.closest("div");
    const editableTextArea = editableTextAreaSection.querySelector(
      "#load_multiple_observables-textArea",
    );
    expect(editableTextArea).toBeInTheDocument();
    // side section with extracted observables
    expect(screen.getByText("No observable found.")).toBeInTheDocument();
    // type some text
    await user.type(editableTextArea, "1.1.1.1, test.it prova");
    expect(
      screen.getByRole("heading", { name: "domain:" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "ip:" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "url:" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "hash:" })).toBeInTheDocument();
    expect(screen.getByText("1.1.1.1")).toBeInTheDocument();
    expect(screen.getByText("test.it")).toBeInTheDocument();

    // extract observables
    const extractButton = screen.getByRole("button", {
      name: "Extract",
    });
    expect(extractButton).toBeInTheDocument();
    await user.click(extractButton);

    // scan page
    const firstObservableInputElement = screen.getAllByRole("textbox", {
      name: "",
    })[0];
    expect(firstObservableInputElement).toBeInTheDocument();
    expect(firstObservableInputElement.value).toBe("test.it");
    const secondObservableInputElement = screen.getAllByRole("textbox", {
      name: "",
    })[1];
    expect(secondObservableInputElement).toBeInTheDocument();
    expect(secondObservableInputElement.value).toBe("1.1.1.1");
  });

  test("test multiple observables of different types and remove duplicates", async () => {
    const user = userEvent.setup();
    render(
      <BrowserRouter>
        <ScanForm />
      </BrowserRouter>,
    );

    const firstObservableInputElement = screen.getByRole("textbox", {
      name: "",
    });
    await user.type(firstObservableInputElement, "google.]com");
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
    await user.type(secondObservableInputElement, "1.1.1.1");

    // add third element (duplicate)
    await user.click(addNewValueButton);
    const thirdObservableInputElement = screen.getAllByRole("textbox", {
      name: "",
    })[2];
    // doubled braked are required by user-event library
    await user.type(thirdObservableInputElement, "1.1.1.1");

    const startScanButton = screen.getByRole("button", { name: "Start Scan" });
    expect(startScanButton).toBeInTheDocument();
    user.click(startScanButton);

    await waitFor(() => {
      // no call to the API to check old analysis (one of the advanced settings)
      expect(axios.post.mock.calls.length).toBe(1);
      expect(axios.post.mock.calls).toEqual([
        [
          PLAYBOOKS_ANALYZE_MULTIPLE_OBSERVABLE_URI,
          {
            observables: [
              ["domain", "google.com"],
              ["ip", "1.1.1.1"],
            ],
            playbook_requested: "TEST_PLAYBOOK_DOMAIN",
            tlp: "CLEAR",
            scan_mode: 2,
            scan_check_time: "48:00:00",
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
  });
});
