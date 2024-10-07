import React from "react";
import "@testing-library/jest-dom";
import axios from "axios";
import { screen, render, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import { API_BASE_URI } from "../../../../../src/constants/apiURLs";
import { PivotConfigForm } from "../../../../../src/components/plugins/forms/PivotConfigForm";
import { mockedUsePluginConfigurationStore } from "../../../../mock";

jest.mock("../../../../../src/stores/usePluginConfigurationStore", () => ({
  usePluginConfigurationStore: jest.fn((state) =>
    state(mockedUsePluginConfigurationStore),
  ),
}));

jest.mock("axios");

describe("PivotConfigForm test", () => {
  const pivotConfig = {
    id: 13,
    name: "test",
    description: "pivot: test",
    python_module: "self_analyzable.SelfAnalyzable",
    playbooks_choice: ["DNS"],
    disabled: false,
    soft_time_limit: 60,
    routing_key: "default",
    health_check_status: true,
    delay: "00:00:00",
    health_check_task: null,
    config: {
      queue: "default",
      soft_time_limit: 60,
    },
    related_analyzer_configs: ["TEST_ANALYZER"],
    secrets: {},
    params: {},
    verification: {
      configured: true,
      details: "Ready to use!",
      missing_secrets: [],
    },
  };

  test("form fields", async () => {
    render(
      <BrowserRouter>
        <PivotConfigForm toggle={jest.fn()} isOpen />
      </BrowserRouter>,
    );

    // form fields
    const nameInputField = screen.getByLabelText("Name:");
    expect(nameInputField).toBeInTheDocument();

    const descriptionInputField = screen.getByLabelText("Description:");
    expect(descriptionInputField).toBeInTheDocument();

    const analyzersInputField = screen.getByText("Analyzers:");
    expect(analyzersInputField).toBeInTheDocument();
    const connectorsInputField = screen.getByText("Connectors:");
    expect(connectorsInputField).toBeInTheDocument();

    const pythonModuleInputField = screen.getByText("Type of pivot:");
    expect(pythonModuleInputField).toBeInTheDocument();

    const playbookInputField = screen.getByText("Playbook to Execute:");
    expect(playbookInputField).toBeInTheDocument();

    const saveButton = screen.getByRole("button", { name: "Save" });
    expect(saveButton).toBeInTheDocument();
    expect(saveButton.className).toContain("disabled");
  });

  test("create pivot config - SelfAnalyzable", async () => {
    const userAction = userEvent.setup();
    axios.post.mockImplementation(() => Promise.resolve({ status: 201 }));

    render(
      <BrowserRouter>
        <PivotConfigForm toggle={jest.fn()} isOpen />
      </BrowserRouter>,
    );

    // form fields
    const nameInputField = screen.getByLabelText("Name:");
    expect(nameInputField).toBeInTheDocument();

    const descriptionInputField = screen.getByLabelText("Description:");
    expect(descriptionInputField).toBeInTheDocument();

    const analyzersInputField = screen.getByText("Analyzers:");
    expect(analyzersInputField).toBeInTheDocument();
    const connectorsInputField = screen.getByText("Connectors:");
    expect(connectorsInputField).toBeInTheDocument();

    const pythonModuleInputField = screen.getByText("Type of pivot:");
    expect(pythonModuleInputField).toBeInTheDocument();

    const playbookInputField = screen.getByText("Playbook to Execute:");
    expect(playbookInputField).toBeInTheDocument();

    const saveButton = screen.getByRole("button", { name: "Save" });
    expect(saveButton).toBeInTheDocument();
    expect(saveButton.className).toContain("disabled");

    // clear editor and type new playbook name
    await userAction.clear(nameInputField);
    await userAction.type(nameInputField, "myNewPivot");

    // select the test analyzer
    const analyzerDropdownButton = screen.getAllByRole("combobox")[0];
    expect(analyzerDropdownButton).toBeInTheDocument();
    await userAction.click(analyzerDropdownButton);

    const testAnalyzerButton = screen.getAllByRole("option")[0];
    expect(testAnalyzerButton).toBeInTheDocument();
    await userAction.click(testAnalyzerButton);

    // select the python module
    const pythonModuleDropdownButton = screen.getAllByRole("combobox")[2];
    expect(pythonModuleDropdownButton).toBeInTheDocument();
    await userAction.click(pythonModuleDropdownButton);

    const pythonModuleButton = screen.getAllByRole("option")[1]; // self analyzable
    expect(pythonModuleButton).toBeInTheDocument();
    await userAction.click(pythonModuleButton);

    // select the playbook
    const playbookDropdownButton = screen.getAllByRole("combobox")[3];
    expect(playbookDropdownButton).toBeInTheDocument();
    await userAction.click(playbookDropdownButton);

    const playbookButton = screen.getAllByRole("option")[1];
    expect(playbookButton).toBeInTheDocument();
    await userAction.click(playbookButton);

    expect(saveButton.className).not.toContain("disabled");
    await userAction.click(saveButton);

    await waitFor(() => {
      expect(axios.post).toHaveBeenCalledWith(`${API_BASE_URI}/pivot`, {
        name: "myNewPivot",
        python_module: "self_analyzable.SelfAnalyzable",
        playbooks_choice: ["TEST_PLAYBOOK_URL"],
        related_analyzer_configs: ["TEST_ANALYZER"],
        related_connector_configs: [],
      });
    });
  });

  test("create pivot config - AnyCompare", async () => {
    const userAction = userEvent.setup();
    axios.post.mockImplementation(() => Promise.resolve({ status: 201 }));

    render(
      <BrowserRouter>
        <PivotConfigForm toggle={jest.fn()} isOpen />
      </BrowserRouter>,
    );

    // form fields
    const nameInputField = screen.getByLabelText("Name:");
    expect(nameInputField).toBeInTheDocument();

    const descriptionInputField = screen.getByLabelText("Description:");
    expect(descriptionInputField).toBeInTheDocument();

    const analyzersInputField = screen.getByText("Analyzers:");
    expect(analyzersInputField).toBeInTheDocument();
    const connectorsInputField = screen.getByText("Connectors:");
    expect(connectorsInputField).toBeInTheDocument();

    const pythonModuleInputField = screen.getByText("Type of pivot:");
    expect(pythonModuleInputField).toBeInTheDocument();

    const playbookInputField = screen.getByText("Playbook to Execute:");
    expect(playbookInputField).toBeInTheDocument();

    const saveButton = screen.getByRole("button", { name: "Save" });
    expect(saveButton).toBeInTheDocument();
    expect(saveButton.className).toContain("disabled");

    // clear editor and type new playbook name
    await userAction.clear(nameInputField);
    await userAction.type(nameInputField, "myNewPivot");

    // select the test analyzer
    const analyzerDropdownButton = screen.getAllByRole("combobox")[0];
    expect(analyzerDropdownButton).toBeInTheDocument();
    await userAction.click(analyzerDropdownButton);

    const testAnalyzerButton = screen.getAllByRole("option")[0];
    expect(testAnalyzerButton).toBeInTheDocument();
    await userAction.click(testAnalyzerButton);

    // select the python module
    const pythonModuleDropdownButton = screen.getAllByRole("combobox")[2];
    expect(pythonModuleDropdownButton).toBeInTheDocument();
    await userAction.click(pythonModuleDropdownButton);

    const testPythonModuleButton = screen.getAllByRole("option")[0]; // any compare
    expect(testPythonModuleButton).toBeInTheDocument();
    await userAction.click(testPythonModuleButton);

    const fieldToCompareInputField = screen.getByText(
      "Dotted path to the field that will be extracted and then analyzed:",
    );
    expect(fieldToCompareInputField).toBeInTheDocument();

    // type field_to_compare
    await userAction.type(fieldToCompareInputField, "test.value");

    // select the playbook
    const playbookDropdownButton = screen.getAllByRole("combobox")[3];
    expect(playbookDropdownButton).toBeInTheDocument();
    await userAction.click(playbookDropdownButton);

    const playbookButton = screen.getAllByRole("option")[1];
    expect(playbookButton).toBeInTheDocument();
    await userAction.click(playbookButton);

    expect(saveButton.className).not.toContain("disabled");
    await userAction.click(saveButton);

    await waitFor(() => {
      expect(axios.post).toHaveBeenCalledWith(`${API_BASE_URI}/pivot`, {
        name: "myNewPivot",
        python_module: "any_compare.AnyCompare",
        playbooks_choice: ["TEST_PLAYBOOK_URL"],
        plugin_config: {
          type: 5,
          plugin_name: "myNewPivot",
          attribute: "field_to_compare",
          value: "test.value",
          config_type: 1,
        },
        related_analyzer_configs: ["TEST_ANALYZER"],
        related_connector_configs: [],
      });
    });
  });

  test("edit pivot config", async () => {
    const userAction = userEvent.setup();
    axios.patch.mockImplementation(() => Promise.resolve({ status: 200 }));

    render(
      <BrowserRouter>
        <PivotConfigForm pivotConfig={pivotConfig} toggle={jest.fn()} isOpen />
      </BrowserRouter>,
    );

    // form fields
    const nameInputField = screen.getByLabelText("Name:");
    expect(nameInputField).toBeInTheDocument();
    expect(nameInputField).toHaveValue("test");

    const descriptionInputField = screen.getByLabelText("Description:");
    expect(descriptionInputField).toBeInTheDocument();
    expect(descriptionInputField).toHaveValue("pivot: test");

    const analyzersInputField = screen.getByText("Analyzers:");
    expect(analyzersInputField).toBeInTheDocument();
    const connectorsInputField = screen.getByText("Connectors:");
    expect(connectorsInputField).toBeInTheDocument();

    const pythonModuleInputField = screen.getByText("Type of pivot:");
    expect(pythonModuleInputField).toBeInTheDocument();

    const playbookInputField = screen.getByText("Playbook to Execute:");
    expect(playbookInputField).toBeInTheDocument();

    const saveButton = screen.getByRole("button", { name: "Save" });
    expect(saveButton).toBeInTheDocument();
    expect(saveButton.className).toContain("disabled");

    // clear editor and type new playbook name
    await userAction.clear(nameInputField);
    await userAction.type(nameInputField, "myNewPivot");

    expect(saveButton.className).not.toContain("disabled");
    await userAction.click(saveButton);

    await waitFor(() => {
      expect(axios.patch).toHaveBeenCalledWith(`${API_BASE_URI}/pivot/test`, {
        name: "myNewPivot",
        python_module: "self_analyzable.SelfAnalyzable",
        playbooks_choice: ["DNS"],
        related_analyzer_configs: ["TEST_ANALYZER"],
        related_connector_configs: [],
      });
    });
  });
});
