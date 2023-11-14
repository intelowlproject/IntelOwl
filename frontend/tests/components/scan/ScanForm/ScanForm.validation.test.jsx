import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import axios from "axios";
import userEvent from "@testing-library/user-event";
import ScanForm from "../../../../src/components/scan/ScanForm";
import RecentScans from "../../../../src/components/scan/utils/RecentScans";

import {
  mockedUseAuthStore,
  mockedUseTagsStore,
  mockedUsePluginConfigurationStore,
} from "../../../mock";

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

describe("test ScanForm component form validation", () => {
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

  test("form validation - selected observable and change the analysis type", async () => {
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
    await waitFor(() => {
      expect(RecentScans).toHaveBeenCalledWith(
        { classification: "domain", param: "google.com" },
        {},
      );
    });
    expect(screen.getByText("TEST_PLAYBOOK_DOMAIN")).toBeInTheDocument();
    const analyzerSelectionRadioButton = screen.getAllByRole("radio")[3];
    expect(analyzerSelectionRadioButton).toBeInTheDocument();
    await user.click(analyzerSelectionRadioButton);
    const playbookSelectionRadioButton = screen.getAllByRole("radio")[2];
    expect(playbookSelectionRadioButton).toBeInTheDocument();
    await user.click(playbookSelectionRadioButton);
    expect(screen.queryByText("TEST_PLAYBOOK_DOMAIN")).toBeInTheDocument();
    const startScanButton = screen.getByRole("button", { name: "Start Scan" });
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).not.toContain("disabled");
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
    await waitFor(() => {
      expect(RecentScans).toHaveBeenCalledWith(
        { classification: "domain", param: "google.com" },
        {},
      );
    });
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
    await waitFor(() => {
      expect(RecentScans).toHaveBeenCalledWith(
        { classification: "domain", param: "google.com" },
        {},
      );
    });
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
    await waitFor(() => {
      expect(RecentScans).toHaveBeenCalledWith(
        { classification: "domain", param: "google.com" },
        {},
      );
    });
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

  test("form validation - file selection and change the analysis type", async () => {
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
    expect(screen.queryByText("TEST_PLAYBOOK_FILE")).toBeInTheDocument();
    // check scan is enabled
    const startScanButton = screen.getByRole("button", { name: "Start Scan" });
    expect(startScanButton).toBeInTheDocument();
    expect(startScanButton.className).not.toContain("disabled");
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
});
