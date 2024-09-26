import React from "react";
import "@testing-library/jest-dom";
import axios from "axios";
import { screen, render, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import { API_BASE_URI } from "../../../../../src/constants/apiURLs";
import { AnalyzerConfigForm } from "../../../../../src/components/plugins/forms/AnalyzerConfigForm";
import { mockedUsePluginConfigurationStore } from "../../../../mock";

jest.mock("../../../../../src/stores/usePluginConfigurationStore", () => ({
  usePluginConfigurationStore: jest.fn((state) =>
    state(mockedUsePluginConfigurationStore),
  ),
}));

jest.mock("axios");

describe("AnalyzerConfigForm test", () => {       
  const analyzerConfig = {
    id: 13,
    name: "test",
    description: "analyzer: test",
    python_module: "basic_observable_analyzer.BasicObservableAnalyzer",
    disabled: false,
    type: "observable",
    docker_based: false,
    maximum_tlp: "AMBER",
    observable_supported: ["domain"],
    config: {
      queue: "default",
      soft_time_limit: 60,
    },
    secrets: {},
    params: {
        attribute: "http_method",
        config_type: 1,
        plugin_name: "myNewAnalyzer",
        type: 1,
        value: "get",
    },
    verification: {
      configured: true,
      details: "Ready to use!",
      missing_secrets: [],
    },
  };

  test("form fields", async () => {
    render(
      <BrowserRouter>
        <AnalyzerConfigForm toggle={jest.fn()} isOpen />
      </BrowserRouter>,
    );

    // form fields
    const nameInputField = screen.getByLabelText("Name:");
    expect(nameInputField).toBeInTheDocument();

    const descriptionInputField = screen.getByLabelText("Description:");
    expect(descriptionInputField).toBeInTheDocument();

    const observableSupportedField = screen.getByText("Observable supported:");
    expect(observableSupportedField).toBeInTheDocument();
    const ipCheckbox = screen.getAllByRole("checkbox")[0];
    expect(ipCheckbox).not.toBeChecked();
    const urlCheckbox = screen.getAllByRole("checkbox")[1];
    expect(urlCheckbox).not.toBeChecked();
    const domainCheckbox = screen.getAllByRole("checkbox")[2];
    expect(domainCheckbox).not.toBeChecked();
    const hashCheckbox = screen.getAllByRole("checkbox")[3];
    expect(hashCheckbox).not.toBeChecked();
    const genericCheckbox = screen.getAllByRole("checkbox")[4];
    expect(genericCheckbox).not.toBeChecked();
 
    const tlpField = screen.getByText("TLP");
    expect(tlpField).toBeInTheDocument();

    const urlInputField = screen.getByText("Url:");
    expect(urlInputField).toBeInTheDocument();

    const httpMethodInputField = screen.getByText("HTTP method:");
    expect(httpMethodInputField).toBeInTheDocument();

    const paramNameInputField = screen.getByText("Param name:");
    expect(paramNameInputField).toBeInTheDocument();

    const userAgentInputField = screen.getByText("User-Agent:");
    expect(userAgentInputField).toBeInTheDocument();

    const authSchemeInputField = screen.getByText("Authentication scheme:");
    expect(authSchemeInputField).toBeInTheDocument();

    const apiKeyInputField = screen.getByText("Api key:");
    expect(apiKeyInputField).toBeInTheDocument();

    const certificateInputField = screen.getByText("Certificate:");
    expect(certificateInputField).toBeInTheDocument();

    const saveButton = screen.getByRole("button", { name: "Save" });
    expect(saveButton).toBeInTheDocument();
    expect(saveButton.className).toContain("disabled");
  });

  test("create analyzer config", async () => {
    const userAction = userEvent.setup();
    axios.post.mockImplementation(() => Promise.resolve({ status: 201 }));

    render(
      <BrowserRouter>
        <AnalyzerConfigForm toggle={jest.fn()} isOpen />
      </BrowserRouter>,
    );

    // form fields
    const nameInputField = screen.getByLabelText("Name:");
    expect(nameInputField).toBeInTheDocument();

    const descriptionInputField = screen.getByLabelText("Description:");
    expect(descriptionInputField).toBeInTheDocument();

    const observableSupportedField = screen.getByText("Observable supported:");
    expect(observableSupportedField).toBeInTheDocument();
    const ipCheckbox = screen.getAllByRole("checkbox")[0];
    expect(ipCheckbox).not.toBeChecked();
    const urlCheckbox = screen.getAllByRole("checkbox")[1];
    expect(urlCheckbox).not.toBeChecked();
    const domainCheckbox = screen.getAllByRole("checkbox")[2];
    expect(domainCheckbox).not.toBeChecked();
    const hashCheckbox = screen.getAllByRole("checkbox")[3];
    expect(hashCheckbox).not.toBeChecked();
    const genericCheckbox = screen.getAllByRole("checkbox")[4];
    expect(genericCheckbox).not.toBeChecked();
 
    const tlpField = screen.getByText("TLP");
    expect(tlpField).toBeInTheDocument();
    const amberTLP = screen.getByRole("radio", { name: "RED" });
    expect(amberTLP).toBeInTheDocument();
    expect(amberTLP).toBeChecked();

    const urlInputField = screen.getByText("Url:");
    expect(urlInputField).toBeInTheDocument();

    const httpMethodInputField = screen.getByText("HTTP method:");
    expect(httpMethodInputField).toBeInTheDocument();

    const paramNameInputField = screen.getByText("Param name:");
    expect(paramNameInputField).toBeInTheDocument();

    const userAgentInputField = screen.getByText("User-Agent:");
    expect(userAgentInputField).toBeInTheDocument();

    const authSchemeInputField = screen.getByText("Authentication scheme:");
    expect(authSchemeInputField).toBeInTheDocument();

    const apiKeyInputField = screen.getByText("Api key:");
    expect(apiKeyInputField).toBeInTheDocument();

    const certificateInputField = screen.getByText("Certificate:");
    expect(certificateInputField).toBeInTheDocument();

    const saveButton = screen.getByRole("button", { name: "Save" });
    expect(saveButton).toBeInTheDocument();
    expect(saveButton.className).toContain("disabled");

    // type name
    await userAction.type(nameInputField, "myNewAnalyzer");
    // type description
    await userAction.type(descriptionInputField, "myNewAnalyzer - description");
    // add ip in supported types
    await userAction.click(ipCheckbox);
    // type url
    await userAction.type(urlInputField, "http://www.google.com");
    
    expect(saveButton.className).not.toContain("disabled");
    await userAction.click(saveButton);

    await waitFor(() => {
      expect(axios.post).toHaveBeenCalledWith(`${API_BASE_URI}/analyzer`, {
        name: "myNewAnalyzer",
        description: "myNewAnalyzer - description",
        python_module: "basic_observable_analyzer.BasicObservableAnalyzer",
        maximum_tlp: "RED",
        observable_supported: ["ip"],
        type: "observable",
        plugin_config: [
            {
                attribute: "http_method",
                config_type: 1,
                plugin_name: "myNewAnalyzer",
                type: 1,
                value: "get",
            },
            {
                attribute: "url",
                config_type: 1,
                plugin_name: "myNewAnalyzer",
                type: 1,
                value: "http://www.google.com",
            },
        ],
      });
    });
  });

  test("edit analyzer config", async () => {
    const userAction = userEvent.setup();
    axios.patch.mockImplementation(() => Promise.resolve({ status: 200 }));

    render(
      <BrowserRouter>
        <AnalyzerConfigForm analyzerConfig={analyzerConfig} toggle={jest.fn()} isOpen />
      </BrowserRouter>,
    );

    // form fields
    const nameInputField = screen.getByLabelText("Name:");
    expect(nameInputField).toBeInTheDocument();

    const descriptionInputField = screen.getByLabelText("Description:");
    expect(descriptionInputField).toBeInTheDocument();

    const observableSupportedField = screen.getByText("Observable supported:");
    expect(observableSupportedField).toBeInTheDocument();
    const ipCheckbox = screen.getAllByRole("checkbox")[0];
    expect(ipCheckbox).not.toBeChecked();
    const urlCheckbox = screen.getAllByRole("checkbox")[1];
    expect(urlCheckbox).not.toBeChecked();
    const domainCheckbox = screen.getAllByRole("checkbox")[2];
    expect(domainCheckbox).not.toBeChecked();
    const hashCheckbox = screen.getAllByRole("checkbox")[3];
    expect(hashCheckbox).not.toBeChecked();
    const genericCheckbox = screen.getAllByRole("checkbox")[4];
    expect(genericCheckbox).not.toBeChecked();
 
    const tlpField = screen.getByText("TLP");
    expect(tlpField).toBeInTheDocument();
    const amberTLP = screen.getByRole("radio", { name: "RED" });
    expect(amberTLP).toBeInTheDocument();
    expect(amberTLP).toBeChecked();

    const urlInputField = screen.getByText("Url:");
    expect(urlInputField).toBeInTheDocument();

    const httpMethodInputField = screen.getByText("HTTP method:");
    expect(httpMethodInputField).toBeInTheDocument();

    const paramNameInputField = screen.getByText("Param name:");
    expect(paramNameInputField).toBeInTheDocument();

    const userAgentInputField = screen.getByText("User-Agent:");
    expect(userAgentInputField).toBeInTheDocument();

    const authSchemeInputField = screen.getByText("Authentication scheme:");
    expect(authSchemeInputField).toBeInTheDocument();

    const apiKeyInputField = screen.getByText("Api key:");
    expect(apiKeyInputField).toBeInTheDocument();

    const certificateInputField = screen.getByText("Certificate:");
    expect(certificateInputField).toBeInTheDocument();

    const saveButton = screen.getByRole("button", { name: "Save" });
    expect(saveButton).toBeInTheDocument();
    expect(saveButton.className).toContain("disabled");

    // clear editor and type new analyzer name and description
    await userAction.clear(nameInputField);
    await userAction.type(nameInputField, "myNewAnalyzer");

    await userAction.clear(descriptionInputField);
    await userAction.type(descriptionInputField, "myNewAnalyzer - description");

    expect(saveButton.className).not.toContain("disabled");
    await userAction.click(saveButton);

    await waitFor(() => {
        expect(axios.patch).toHaveBeenCalledWith(`${API_BASE_URI}/analyzer/test`, {
          name: "myNewAnalyzer",
          description: "myNewAnalyzer - description",
          python_module: "basic_observable_analyzer.BasicObservableAnalyzer",
          maximum_tlp: "RED",
          observable_supported: ["ip"],
          type: "observable",
          plugin_config: [
              {
                  attribute: "http_method",
                  config_type: 1,
                  plugin_name: "myNewAnalyzer",
                  type: 1,
                  value: "get",
              },
              {
                  attribute: "url",
                  config_type: 1,
                  plugin_name: "myNewAnalyzer",
                  type: 1,
                  value: "http://www.google.com",
              },
          ],
        });
      });
  });
});
