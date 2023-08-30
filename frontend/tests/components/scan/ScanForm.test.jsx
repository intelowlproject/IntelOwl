import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Routes, Route, BrowserRouter } from "react-router-dom";
import axios from "axios";
import userEvent from "@testing-library/user-event";
import ScanForm from "../../../src/components/scan/ScanForm";
import {
  ANALYZE_MULTIPLE_FILES_URI,
  ANALYZE_MULTIPLE_OBSERVABLE_URI,
  PLAYBOOKS_ANALYZE_MULTIPLE_FILES_URI,
  PLAYBOOKS_ANALYZE_MULTIPLE_OBSERVABLE_URI,
} from "../../../src/constants/api";
import { RecentScans } from "../../../src/components/scan/utils";

jest.mock("axios");
// IMPORTANT: this mocks work with several storages because all of them are imported from index!
jest.mock("../../../src/stores", () => ({
  useAuthStore: jest.fn((state) =>
    state({
      loading: false,
      token: null,
      user: {
        username: "test",
        full_name: "test user",
        first_name: "test",
        last_name: "user",
        email: "test@google.com",
      },
      access: {
        total_submissions: 10,
        month_submissions: 2,
      },
      isAuthenticated: () => false,
      updateToken: () => {},
      deleteToken: () => {},
      service: {
        fetchUserAccess: () => {},
        loginUser: () => {},
        logoutUser: () => {},
        forceLogout: () => {},
      },
    }),
  ),
  useTagsStore: jest.fn((state) =>
    state({
      loading: false,
      error: null,
      tags: [
        {
          id: 1,
          label: "test tag",
          color: "#1655D3",
        },
      ],
      list: () => {},
      create: () => {},
      update: () => {},
    }),
  ),
  usePluginConfigurationStore: jest.fn((state) =>
    state({
      analyzersLoading: false,
      connectorsLoading: false,
      visualizersLoading: false,
      playbooksLoading: false,
      analyzersError: null,
      connectorsError: null,
      playbooksError: null,
      visualizersError: null,
      analyzers: [
        {
          name: "TEST_ANALYZER",
          config: {
            queue: "default",
            soft_time_limit: 30,
          },
          python_module: "test.Test",
          description: "Test analyzer",
          disabled: false,
          type: "observable",
          docker_based: false,
          maximum_tlp: "AMBER",
          observable_supported: [
            "domain",
            "generic",
            "hash",
            "ip",
            "url",
            "file",
          ],
          supported_filetypes: [],
          run_hash: false,
          run_hash_type: "",
          not_supported_filetypes: [],
          params: {},
          secrets: {},
          verification: {
            configured: true,
            details: "Ready to use!",
            missing_secrets: [],
          },
          orgPluginDisabled: false,
          plugin_type: "1",
        },
      ],
      connectors: [],
      visualizers: [],
      playbooks: [
        {
          name: "TEST_PLAYBOOK_IP",
          type: ["ip"],
          description: "Test playbook for the IP addresses",
          disabled: false,
          runtime_configuration: {
            analyzers: {},
            connectors: {},
            visualizers: {},
          },
          analyzers: [],
          connectors: [],
          scan_mode: 2,
          scan_check_time: "2 00:00:00",
          tags: [
            {
              id: 1,
              label: "test tag",
              color: "#1655D3",
            },
          ],
          tlp: "CLEAR",
        },
        {
          name: "TEST_PLAYBOOK_DOMAIN",
          type: ["domain"],
          description: "Test playbook for the domains",
          disabled: false,
          runtime_configuration: {
            analyzers: {},
            connectors: {},
            visualizers: {},
          },
          analyzers: [],
          connectors: [],
          scan_mode: 2,
          scan_check_time: "2 00:00:00",
          tags: [],
          tlp: "CLEAR",
        },
        {
          name: "TEST_PLAYBOOK_URL",
          type: ["url"],
          description: "Test playbook for the URLs",
          disabled: false,
          runtime_configuration: {
            analyzers: {},
            connectors: {},
            visualizers: {},
          },
          analyzers: [],
          connectors: [],
          scan_mode: 1,
          scan_check_time: null,
          tags: [],
          tlp: "AMBER",
        },
        {
          name: "TEST_PLAYBOOK_HASH",
          type: ["hash"],
          description: "Test playbook for the hashes",
          disabled: false,
          runtime_configuration: {
            analyzers: {},
            connectors: {},
            visualizers: {},
          },
          analyzers: [],
          connectors: [],
          scan_mode: 1,
          scan_check_time: null,
          tags: [],
          tlp: "AMBER",
        },
        {
          name: "TEST_PLAYBOOK_FILE",
          type: ["file"],
          description: "Test playbook for the files",
          disabled: false,
          runtime_configuration: {
            analyzers: {},
            connectors: {},
            visualizers: {},
          },
          analyzers: [],
          connectors: [],
          scan_mode: 1,
          scan_check_time: null,
          tags: [],
          tlp: "AMBER",
        },
        {
          name: "TEST_PLAYBOOK_GENERIC",
          type: ["generic"],
          description: "Test playbook for the generic observables",
          disabled: false,
          runtime_configuration: {
            analyzers: {},
            connectors: {},
            visualizers: {},
          },
          analyzers: [],
          connectors: [],
          scan_mode: 1,
          scan_check_time: null,
          tags: [],
          tlp: "AMBER",
        },
      ],
      hydrate: () => {},
      retrieveAnalyzersConfiguration: () => {},
      retrieveConnectorsConfiguration: () => {},
      retrieveVisualizersConfiguration: () => {},
      retrieveIngestorsConfiguration: () => {},
      retrievePlaybooksConfiguration: () => {},
      checkPluginHealth: () => {},
    }),
  ),
}));
// mock RecentScans component
jest.mock("../../../src/components/scan/utils/RecentScans", () =>
  jest.fn((props) => <div {...props} />),
);

describe("test ScanForm component", () => {
  /* those tests could require lots of time, jest.setTimeout doesn't work on async function.
        use the second param of async instead.
    */

  beforeAll(() => {
    axios.post.mockImplementation(() =>
      Promise.resolve({ data: { results: [], count: 0 } }),
    );
  });

  test("form validation - default", async () => {
    render(
      <BrowserRouter>
        <ScanForm />
      </BrowserRouter>,
    );
    const startScanButton = screen.getByRole("button", { name: "Start Scan" });
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).toContain("disabled");
    expect(RecentScans).toHaveBeenCalledWith(
      { classification: "generic", param: "" },
      {},
    );
  });

  test("form validation - no observable selection and playbook", async () => {
    const user = userEvent.setup();

    const { container } = render(
      <BrowserRouter>
        <ScanForm />
      </BrowserRouter>,
    );

    // no observable and playbook
    const firstObservableInputElement = screen.getByRole("textbox", {
      name: "",
    });
    expect(firstObservableInputElement).toBeInTheDocument();
    expect(firstObservableInputElement.value).toBe("");
    const playbookDropdownButton = screen.getAllByRole("combobox")[0];
    expect(playbookDropdownButton).toBeInTheDocument();
    await user.click(playbookDropdownButton);
    /* the id change in case you run a single test or all of them.
        we need this strange way to access instead of the id */
    const testPlaybookButton = container.querySelector(
      `#${playbookDropdownButton.id.replace("-input", "")}-option-0`,
    );
    expect(testPlaybookButton).toBeInTheDocument();
    await user.click(testPlaybookButton);
    expect(screen.getByText("TEST_PLAYBOOK_GENERIC")).toBeInTheDocument();
    const startScanButton = screen.getByRole("button", { name: "Start Scan" });
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).toContain("disabled");
    expect(RecentScans).toHaveBeenCalledWith(
      { classification: "generic", param: "" },
      {},
    );
  });

  test("form validation - observable selected and no playbook", async () => {
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <ScanForm />
      </BrowserRouter>,
    );

    // no observable and playbook
    const firstObservableInputElement = screen.getByRole("textbox", {
      name: "",
    });
    expect(firstObservableInputElement).toBeInTheDocument();
    await user.type(firstObservableInputElement, "google.com");
    expect(firstObservableInputElement.value).toBe("google.com");
    expect(screen.getByText("TEST_PLAYBOOK_DOMAIN")).toBeInTheDocument();
    const analyzerSelectionRadioButton = screen.getAllByRole("radio")[3];
    expect(analyzerSelectionRadioButton).toBeInTheDocument();
    await user.click(analyzerSelectionRadioButton);
    const playbookSelectionRadioButton = screen.getAllByRole("radio")[2];
    expect(playbookSelectionRadioButton).toBeInTheDocument();
    await user.click(playbookSelectionRadioButton);
    expect(screen.queryByText("TEST_PLAYBOOK_DOMAIN")).toBeNull();
    const startScanButton = screen.getByRole("button", { name: "Start Scan" });
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).toContain("disabled");
    expect(RecentScans).toHaveBeenCalledWith(
      { classification: "domain", param: "google.com" },
      {},
    );
  });

  test("form validation - observable and playbook selected", async () => {
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <ScanForm />
      </BrowserRouter>,
    );

    const firstObservableInputElement = screen.getByRole("textbox", {
      name: "",
    });
    expect(firstObservableInputElement).toBeInTheDocument();
    await user.type(firstObservableInputElement, "google.com");
    expect(firstObservableInputElement.value).toBe("google.com");
    expect(screen.getByText("TEST_PLAYBOOK_DOMAIN")).toBeInTheDocument();
    const startScanButton = screen.getByRole("button", { name: "Start Scan" });
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).not.toContain("disabled");
    expect(RecentScans).toHaveBeenCalledWith(
      { classification: "domain", param: "google.com" },
      {},
    );
  });

  test("form validation - observable and no analyzer selected", async () => {
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <ScanForm />
      </BrowserRouter>,
    );

    // select analyzers
    const analyzerSelectionRadioButton = screen.getAllByRole("radio")[3];
    expect(analyzerSelectionRadioButton).toBeInTheDocument();
    await user.click(analyzerSelectionRadioButton);
    expect(screen.getByText("Select Analyzers")).toBeInTheDocument();
    expect(screen.getByText("Select Connectors")).toBeInTheDocument();

    const firstObservableInputElement = screen.getByRole("textbox", {
      name: "",
    });
    expect(firstObservableInputElement).toBeInTheDocument();
    await user.type(firstObservableInputElement, "google.com");
    expect(firstObservableInputElement.value).toBe("google.com");
    const startScanButton = screen.getByRole("button", { name: "Start Scan" });
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).toContain("disabled");
    expect(RecentScans).toHaveBeenCalledWith(
      { classification: "domain", param: "google.com" },
      {},
    );
  });

  test("form validation - no observable and analyzer selected", async () => {
    const user = userEvent.setup();

    const { container } = render(
      <BrowserRouter>
        <ScanForm />
      </BrowserRouter>,
    );

    const firstObservableInputElement = screen.getByRole("textbox", {
      name: "",
    });
    expect(firstObservableInputElement).toBeInTheDocument();
    expect(firstObservableInputElement.value).toBe("");

    // select analyzers
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

    const startScanButton = screen.getByRole("button", { name: "Start Scan" });
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).toContain("disabled");
    expect(RecentScans).toHaveBeenCalledWith(
      { classification: "generic", param: "" },
      {},
    );
  });

  // observable and analyzers
  test("form validation - observable and analyzer selected", async () => {
    const user = userEvent.setup();

    const { container } = render(
      <BrowserRouter>
        <ScanForm />
      </BrowserRouter>,
    );

    const firstObservableInputElement = screen.getByRole("textbox", {
      name: "",
    });
    expect(firstObservableInputElement).toBeInTheDocument();
    await user.type(firstObservableInputElement, "google.com");
    expect(firstObservableInputElement.value).toBe("google.com");

    // select analyzers
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

    const startScanButton = screen.getByRole("button", { name: "Start Scan" });
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).not.toContain("disabled");
    expect(RecentScans).toHaveBeenCalledWith(
      { classification: "domain", param: "google.com" },
      {},
    );
  });

  test("form validation - no file selection and playbook", async () => {
    const user = userEvent.setup();

    const { container } = render(
      <BrowserRouter>
        <ScanForm />
      </BrowserRouter>,
    );

    // select file section
    const fileSelectionRadioButton = screen.getAllByRole("radio")[1];
    expect(fileSelectionRadioButton).toBeInTheDocument();
    await user.click(fileSelectionRadioButton);
    expect(screen.getByText("File(s)")).toBeInTheDocument();

    /* the id change in case you run a single test or all of them.
        we need this strange way to access instead of the id */
    const playbookDropdownButton = screen.getAllByRole("combobox")[0];
    expect(playbookDropdownButton).toBeInTheDocument();
    await user.click(playbookDropdownButton);
    const testAnalyzerButton = container.querySelector(
      `#${playbookDropdownButton.id.replace("-input", "")}-option-0`,
    );
    expect(testAnalyzerButton).toBeInTheDocument();
    await user.click(testAnalyzerButton);
    expect(screen.getByText("TEST_PLAYBOOK_FILE")).toBeInTheDocument();
    // check scan is enabled
    const startScanButton = screen.getByRole("button", { name: "Start Scan" });
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).toContain("disabled");
    expect(RecentScans).toHaveBeenCalledWith(
      { classification: "file", param: "" },
      {},
    );
  });

  // file and no playbook
  test("form validation - file selection and no playbook", async () => {
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <ScanForm />
      </BrowserRouter>,
    );

    // select file section
    const fileSelectionRadioButton = screen.getAllByRole("radio")[1];
    expect(fileSelectionRadioButton).toBeInTheDocument();
    await user.click(fileSelectionRadioButton);
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

    expect(screen.getByText("TEST_PLAYBOOK_FILE")).toBeInTheDocument();
    const analyzerSelectionRadioButton = screen.getAllByRole("radio")[3];
    expect(analyzerSelectionRadioButton).toBeInTheDocument();
    await user.click(analyzerSelectionRadioButton);
    const playbookSelectionRadioButton = screen.getAllByRole("radio")[2];
    expect(playbookSelectionRadioButton).toBeInTheDocument();
    await user.click(playbookSelectionRadioButton);
    expect(screen.queryByText("TEST_PLAYBOOK_FILE")).toBeNull();
    // check scan is enabled
    const startScanButton = screen.getByRole("button", { name: "Start Scan" });
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).toContain("disabled");
    expect(RecentScans).toHaveBeenCalledWith(
      { classification: "file", param: testImageFiles[0] },
      {},
    );
  });

  // file and playbook
  test("form validation - file selection and playbook", async () => {
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <ScanForm />
      </BrowserRouter>,
    );

    // select file section
    const fileSelectionRadioButton = screen.getAllByRole("radio")[1];
    expect(fileSelectionRadioButton).toBeInTheDocument();
    await user.click(fileSelectionRadioButton);
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
    expect(screen.getByText("TEST_PLAYBOOK_FILE")).toBeInTheDocument();
    // check scan is enabled
    const startScanButton = screen.getByRole("button", { name: "Start Scan" });
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).not.toContain("disabled");
    expect(RecentScans).toHaveBeenCalledWith(
      { classification: "file", param: testImageFiles[0] },
      {},
    );
  });

  test("form validation - no file and analyzer", async () => {
    const user = userEvent.setup();

    const { container } = render(
      <BrowserRouter>
        <ScanForm />
      </BrowserRouter>,
    );

    // select file section
    const fileSelectionRadioButton = screen.getAllByRole("radio")[1];
    expect(fileSelectionRadioButton).toBeInTheDocument();
    await user.click(fileSelectionRadioButton);
    expect(screen.getByText("File(s)")).toBeInTheDocument();

    // select analyzers
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
    const startScanButton = screen.getByRole("button", { name: "Start Scan" });
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).toContain("disabled");
    expect(RecentScans).toHaveBeenCalledWith(
      { classification: "file", param: "" },
      {},
    );
  });

  test("form validation - file and no analyzer", async () => {
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <ScanForm />
      </BrowserRouter>,
    );

    // select file section
    const fileSelectionRadioButton = screen.getAllByRole("radio")[1];
    expect(fileSelectionRadioButton).toBeInTheDocument();
    await user.click(fileSelectionRadioButton);
    expect(screen.getByText("File(s)")).toBeInTheDocument();

    // select analyzers section
    const analyzerSelectionRadioButton = screen.getAllByRole("radio")[3];
    expect(analyzerSelectionRadioButton).toBeInTheDocument();
    await user.click(analyzerSelectionRadioButton);
    expect(screen.getByText("Select Analyzers")).toBeInTheDocument();
    expect(screen.getByText("Select Connectors")).toBeInTheDocument();

    // select file
    const fileInputComponent = screen.getByLabelText("File(s)");
    const testImageFiles = [
      new File(["this is a text line"], "test1.txt", { type: "plain/text" }),
    ];
    await user.upload(fileInputComponent, testImageFiles);
    expect(fileInputComponent.files).toHaveLength(1);
    expect(fileInputComponent.files[0]).toStrictEqual(testImageFiles[0]);
    expect(fileInputComponent.files.item(0)).toStrictEqual(testImageFiles[0]);

    // check scan is enabled
    const startScanButton = screen.getByRole("button", { name: "Start Scan" });
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).toContain("disabled");
    expect(RecentScans).toHaveBeenCalledWith(
      { classification: "file", param: testImageFiles[0] },
      {},
    );
  });

  test("form validation - file and analyzer", async () => {
    const user = userEvent.setup();

    const { container } = render(
      <BrowserRouter>
        <ScanForm />
      </BrowserRouter>,
    );

    // select file section
    const fileSelectionRadioButton = screen.getAllByRole("radio")[1];
    expect(fileSelectionRadioButton).toBeInTheDocument();
    await user.click(fileSelectionRadioButton);
    expect(screen.getByText("File(s)")).toBeInTheDocument();

    // select analyzers section
    const analyzerSelectionRadioButton = screen.getAllByRole("radio")[3];
    expect(analyzerSelectionRadioButton).toBeInTheDocument();
    await user.click(analyzerSelectionRadioButton);
    expect(screen.getByText("Select Analyzers")).toBeInTheDocument();
    expect(screen.getByText("Select Connectors")).toBeInTheDocument();

    // select file
    const fileInputComponent = screen.getByLabelText("File(s)");
    const testImageFiles = [
      new File(["this is a text line"], "test1.txt", { type: "plain/text" }),
    ];
    await user.upload(fileInputComponent, testImageFiles);
    expect(fileInputComponent.files).toHaveLength(1);
    expect(fileInputComponent.files[0]).toStrictEqual(testImageFiles[0]);
    expect(fileInputComponent.files.item(0)).toStrictEqual(testImageFiles[0]);

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
    const startScanButton = screen.getByRole("button", { name: "Start Scan" });
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).not.toContain("disabled");
    // recent scans
    expect(RecentScans).toHaveBeenCalledWith(
      { classification: "file", param: testImageFiles[0] },
      {},
    );
  });

  test(
    "test playbooks advanced change time",
    async () => {
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

      // recent scans
      expect(RecentScans).toHaveBeenCalledWith(
        { classification: "generic", param: "" },
        {},
      );
      
      const startScanButton = screen.getByRole("button", {
        name: "Start Scan",
      });
      expect(startScanButton).toBeInTheDocument();
      expect(startScanButton.className).not.toContain("disabled");
      // recent scans
      expect(RecentScans).toHaveBeenCalledWith(
        { classification: "domain", param: "google.com" },
        {},
      );
      await user.click(startScanButton);

      await waitFor(() => {
        expect(axios.post.mock.calls[0]).toEqual(
          // axios call
          [
            PLAYBOOKS_ANALYZE_MULTIPLE_OBSERVABLE_URI,
            {
              observables: [["domain", "google.com"]],
              playbook_requested: "TEST_PLAYBOOK_DOMAIN",
              tags_labels: [],
              tlp: "CLEAR",
              scan_mode: 2,
              scan_check_time: "10:00:00",
            },
          ],
        );
      });
    },
    15 * 1000,
  );

  test(
    "test analyzers advanced change time",
    async () => {
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
      expect(RecentScans).toHaveBeenCalledWith(
        { classification: "domain", param: "google.com" },
        {},
      );
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
              connectors_requested: [],
              tlp: "AMBER",
              runtime_configuration: {},
              tags_labels: [],
              scan_mode: 2,
              scan_check_time: "10:00:00",
            },
          ],
        );
      });
    },
    15 * 1000,
  );

  test(
    "test observable playbooks advanced settings (force analysis, tlp and tags)",
    async () => {
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
      // recent scans
      expect(RecentScans).toHaveBeenCalledWith(
        { classification: "domain", param: "google.com" },
        {},
      );
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
              scan_check_time: null,
            },
          ],
        ]);
      });
    },
    15 * 1000,
  );

  test(
    "test file playbooks advanced settings (force analysis, tlp and tags)",
    async () => {
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
        });
      });
    },
    15 * 1000,
  );

  test(
    "test observable analyzers advanced settings (force analysis, tlp and tags)",
    async () => {
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

      // recent scans
      expect(RecentScans).toHaveBeenCalledWith(
        { classification: "domain", param: "google.com" },
        {},
      );

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
              connectors_requested: [],
              tags_labels: ["test tag"],
              runtime_configuration: {},
              tlp: "GREEN",
              scan_mode: 1,
              scan_check_time: null,
            },
          ],
        ]);
      });
    },
    15 * 1000,
  );

  test(
    "test file analyzers advanced settings (force analysis, tlp and tags)",
    async () => {
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
      });
    },
    15 * 1000,
  );

  test(
    "domains playbook analysis",
    async () => {
      const user = userEvent.setup();

      render(
        <BrowserRouter>
          <ScanForm />
        </BrowserRouter>,
      );

      const firstObservableInputElement = screen.getByRole("textbox", {
        name: "",
      });
      await user.type(firstObservableInputElement, "google.com");
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
      await user.type(secondObservableInputElement, "microsoft[[.]]com");

      // check playbooks has been loaded
      expect(screen.getByText("TEST_PLAYBOOK_DOMAIN")).toBeInTheDocument();
      // check scan is enabled
      const startScanButton = screen.getByRole("button", {
        name: "Start Scan",
      });
      expect(startScanButton).toBeInTheDocument();
      expect(startScanButton.className).not.toContain("disabled");

      // recent scans
      expect(RecentScans).toHaveBeenCalledWith(
        { classification: "domain", param: "google.com" },
        {},
      );

      await user.click(startScanButton);
      await waitFor(() => {
        expect(axios.post.mock.calls).toEqual([
          // axios call: start new analysis
          [
            PLAYBOOKS_ANALYZE_MULTIPLE_OBSERVABLE_URI,
            {
              observables: [
                ["domain", "google.com"],
                ["domain", "microsoft.com"],
              ],
              playbook_requested: "TEST_PLAYBOOK_DOMAIN",
              tags_labels: [],
              tlp: "CLEAR",
              scan_mode: 2,
              scan_check_time: "48:00:00",
            },
          ],
        ]);
      });
    },
    15 * 1000,
  );

  test(
    "domains analyzer analysis",
    async () => {
      const user = userEvent.setup();

      const { container } = render(
        <BrowserRouter>
          <ScanForm />
        </BrowserRouter>,
      );

      const firstObservableInputElement = screen.getByRole("textbox", {
        name: "",
      });
      await user.type(firstObservableInputElement, "google.com");
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
      await user.type(secondObservableInputElement, "microsoft[[.]]com");

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

      // recent scans
      expect(RecentScans).toHaveBeenCalledWith(
        { classification: "domain", param: "google.com" },
        {},
      );

      await user.click(startScanButton);
      await waitFor(() => {
        expect(axios.post.mock.calls).toEqual([
          // axios call: start new analysis
          [
            ANALYZE_MULTIPLE_OBSERVABLE_URI,
            {
              observables: [
                ["domain", "google.com"],
                ["domain", "microsoft.com"],
              ],
              analyzers_requested: ["TEST_ANALYZER"],
              connectors_requested: [],
              tags_labels: [],
              runtime_configuration: {},
              tlp: "AMBER",
              scan_mode: 2,
              scan_check_time: "24:00:00",
            },
          ],
        ]);
      });
    },
    15 * 1000,
  );

  test(
    "IP address playbook analysis",
    async () => {
      const user = userEvent.setup();

      render(
        <BrowserRouter>
          <ScanForm />
        </BrowserRouter>,
      );

      const firstObservableInputElement = screen.getByRole("textbox", {
        name: "",
      });
      await user.type(firstObservableInputElement, "8.8.8.8");
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
      await user.type(secondObservableInputElement, "1[[.]]1[[.]]1[[.]]1");

      // check playbooks has been loaded
      expect(screen.getByText("TEST_PLAYBOOK_IP")).toBeInTheDocument();
      // check scan is enabled
      const startScanButton = screen.getByRole("button", {
        name: "Start Scan",
      });
      expect(startScanButton).toBeInTheDocument();
      expect(startScanButton.className).not.toContain("disabled");

      // recent scans
      expect(RecentScans).toHaveBeenCalledWith(
        { classification: "ip", param: "8.8.8.8" },
        {},
      );

      await user.click(startScanButton);
      await waitFor(() => {
        expect(axios.post.mock.calls).toEqual([
          // axios call: start new analysis
          [
            PLAYBOOKS_ANALYZE_MULTIPLE_OBSERVABLE_URI,
            {
              observables: [
                ["ip", "8.8.8.8"],
                ["ip", "1.1.1.1"],
              ],
              playbook_requested: "TEST_PLAYBOOK_IP",
              tags_labels: ["test tag"],
              tlp: "CLEAR",
              scan_mode: 2,
              scan_check_time: "48:00:00",
            },
          ],
        ]);
      });
    },
    15 * 1000,
  );

  test(
    "IP address analyzer analysis",
    async () => {
      const user = userEvent.setup();

      const { container } = render(
        <BrowserRouter>
          <ScanForm />
        </BrowserRouter>,
      );

      const firstObservableInputElement = screen.getByRole("textbox", {
        name: "",
      });
      await user.type(firstObservableInputElement, "8.8.8.8");
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
      await user.type(secondObservableInputElement, "1[[.]]1[[.]]1[[.]]1");

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

      // recent scans
      expect(RecentScans).toHaveBeenCalledWith(
        { classification: "ip", param: "8.8.8.8" },
        {},
      );

      await user.click(startScanButton);
      await waitFor(() => {
        expect(axios.post.mock.calls).toEqual([
          // axios call: start new analysis
          [
            ANALYZE_MULTIPLE_OBSERVABLE_URI,
            {
              observables: [
                ["ip", "8.8.8.8"],
                ["ip", "1.1.1.1"],
              ],
              analyzers_requested: ["TEST_ANALYZER"],
              connectors_requested: [],
              tags_labels: [],
              runtime_configuration: {},
              tlp: "AMBER",
              scan_mode: 2,
              scan_check_time: "24:00:00",
            },
          ],
        ]);
      });
    },
    15 * 1000,
  );

  test(
    "URL playbook analysis",
    async () => {
      const user = userEvent.setup();

      render(
        <BrowserRouter>
          <ScanForm />
        </BrowserRouter>,
      );

      const firstObservableInputElement = screen.getByRole("textbox", {
        name: "",
      });
      await user.type(firstObservableInputElement, "https://google.com");
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
      await user.type(
        secondObservableInputElement,
        "https://microsoft[[.]]com",
      );

      // check playbooks has been loaded
      expect(screen.getByText("TEST_PLAYBOOK_URL")).toBeInTheDocument();
      // check scan is enabled
      const startScanButton = screen.getByRole("button", {
        name: "Start Scan",
      });
      expect(startScanButton).toBeInTheDocument();
      expect(startScanButton.className).not.toContain("disabled");

      // recent scans
      expect(RecentScans).toHaveBeenCalledWith(
        { classification: "url", param: "https://google.com" },
        {},
      );

      await user.click(startScanButton);
      await waitFor(() => {
        expect(axios.post.mock.calls).toEqual([
          // axios call: start new analysis
          [
            PLAYBOOKS_ANALYZE_MULTIPLE_OBSERVABLE_URI,
            {
              observables: [
                ["url", "https://google.com"],
                ["url", "https://microsoft.com"],
              ],
              playbook_requested: "TEST_PLAYBOOK_URL",
              tags_labels: [],
              tlp: "AMBER",
              scan_mode: 1,
              scan_check_time: null,
            },
          ],
        ]);
      });
    },
    15 * 1000,
  );

  test(
    "URL analyzer analysis",
    async () => {
      const user = userEvent.setup();

      const { container } = render(
        <BrowserRouter>
          <ScanForm />
        </BrowserRouter>,
      );

      const firstObservableInputElement = screen.getByRole("textbox", {
        name: "",
      });
      await user.type(firstObservableInputElement, "https://google.com");
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
      await user.type(
        secondObservableInputElement,
        "https://microsoft[[.]]com",
      );

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

      // recent scans
      expect(RecentScans).toHaveBeenCalledWith(
        { classification: "url", param: "https://google.com" },
        {},
      );

      await user.click(startScanButton);
      await waitFor(() => {
        expect(axios.post.mock.calls).toEqual([
          // axios call: start new analysis
          [
            ANALYZE_MULTIPLE_OBSERVABLE_URI,
            {
              observables: [
                ["url", "https://google.com"],
                ["url", "https://microsoft.com"],
              ],
              analyzers_requested: ["TEST_ANALYZER"],
              connectors_requested: [],
              tags_labels: [],
              runtime_configuration: {},
              tlp: "AMBER",
              scan_mode: 2,
              scan_check_time: "24:00:00",
            },
          ],
        ]);
      });
    },
    15 * 1000,
  );

  test(
    "HASH playbook analysis",
    async () => {
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
        "1d5920f4b44b27a802bd77c4f0536f5a",
      );
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
      await user.type(
        secondObservableInputElement,
        "ff5c054c7cd6924c570f944007ccf076",
      );

      // check playbooks has been loaded
      expect(screen.getByText("TEST_PLAYBOOK_HASH")).toBeInTheDocument();
      // check scan is enabled
      const startScanButton = screen.getByRole("button", {
        name: "Start Scan",
      });
      expect(startScanButton).toBeInTheDocument();
      expect(startScanButton.className).not.toContain("disabled");

      // recent scans
      expect(RecentScans).toHaveBeenCalledWith(
        { classification: "hash", param: "1d5920f4b44b27a802bd77c4f0536f5a" },
        {},
      );

      await user.click(startScanButton);
      await waitFor(() => {
        expect(axios.post.mock.calls).toEqual([
          // axios call: start new analysis
          [
            PLAYBOOKS_ANALYZE_MULTIPLE_OBSERVABLE_URI,
            {
              observables: [
                ["hash", "1d5920f4b44b27a802bd77c4f0536f5a"],
                ["hash", "ff5c054c7cd6924c570f944007ccf076"],
              ],
              playbook_requested: "TEST_PLAYBOOK_HASH",
              tags_labels: [],
              tlp: "AMBER",
              scan_mode: 1,
              scan_check_time: null,
            },
          ],
        ]);
      });
    },
    15 * 1000,
  );

  test(
    "HASH analyzer analysis",
    async () => {
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
        "1d5920f4b44b27a802bd77c4f0536f5a",
      );
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
      await user.type(
        secondObservableInputElement,
        "ff5c054c7cd6924c570f944007ccf076",
      );

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

      // recent scans
      expect(RecentScans).toHaveBeenCalledWith(
        { classification: "hash", param: "1d5920f4b44b27a802bd77c4f0536f5a" },
        {},
      );

      await user.click(startScanButton);
      await waitFor(() => {
        expect(axios.post.mock.calls).toEqual([
          // axios call: start new analysis
          [
            ANALYZE_MULTIPLE_OBSERVABLE_URI,
            {
              observables: [
                ["hash", "1d5920f4b44b27a802bd77c4f0536f5a"],
                ["hash", "ff5c054c7cd6924c570f944007ccf076"],
              ],
              analyzers_requested: ["TEST_ANALYZER"],
              connectors_requested: [],
              tags_labels: [],
              runtime_configuration: {},
              tlp: "AMBER",
              scan_mode: 2,
              scan_check_time: "24:00:00",
            },
          ],
        ]);
      });
    },
    15 * 1000,
  );

  test(
    "generic playbook analysis",
    async () => {
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

      // check playbooks has been loaded
      expect(screen.getByText("TEST_PLAYBOOK_GENERIC")).toBeInTheDocument();
      // check scan is enabled
      const startScanButton = screen.getByRole("button", {
        name: "Start Scan",
      });
      expect(startScanButton).toBeInTheDocument();
      expect(startScanButton.className).not.toContain("disabled");

      // recent scans
      expect(RecentScans).toHaveBeenCalledWith(
        { classification: "generic", param: "genericText" },
        {},
      );

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
              tags_labels: [],
              tlp: "AMBER",
              scan_mode: 1,
              scan_check_time: null,
            },
          ],
        ]);
      });
    },
    15 * 1000,
  );

  test(
    "generic analyzer analysis",
    async () => {
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
              connectors_requested: [],
              tags_labels: [],
              runtime_configuration: {},
              tlp: "AMBER",
              scan_mode: 2,
              scan_check_time: "24:00:00",
            },
          ],
        ]);
      });
    },
    15 * 1000,
  );

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
        tlp: "AMBER",
        scan_mode: "1",
      });
    });
  });

  test(
    "file analyzer analysis",
    async () => {
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
      });
    },
    15 * 1000,
  );

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
});
