import React from "react";
import "@testing-library/jest-dom";
import axios from "axios";
import { screen, render, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import { PLAYBOOKS_CONFIG_URI } from "../../../../src/constants/apiURLs";
import { PlaybookConfigForm } from "../../../../src/components/plugins/forms/PlaybookConfigForm";
import { mockedUsePluginConfigurationStore } from "../../../mock";

jest.mock("../../../../src/stores/usePluginConfigurationStore", () => ({
  usePluginConfigurationStore: jest.fn((state) =>
    state(mockedUsePluginConfigurationStore),
  ),
}));

jest.mock("axios");
// mock runtimeConfigurationParam
jest.mock(
  "../../../../src/components/common/form/runtimeConfigurationInput",
  () => ({
    ...jest.requireActual(
      "../../../../src/components/common/form/runtimeConfigurationInput",
    ),
    runtimeConfigurationParam: () => {
      const selectedPluginsParams = {
        analyzers: {
          TEST_ANALYZER: {
            query_type: {
              type: "str",
              description: "Test analyzer param description.",
              required: false,
              value: "A",
              is_secret: false,
            },
          },
        },
        connectors: {
          TEST_CONNECTOR: {},
        },
        pivots: {},
        visualizers: {},
      };
      const editableConfig = {
        analyzers: {
          TEST_ANALYZER: { query_type: "A" },
        },
        connectors: {
          TEST_CONNECTOR: {},
        },
        pivots: {},
        visualizers: {},
      };
      return [selectedPluginsParams, editableConfig];
    },
  }),
);

describe("PlaybookConfigForm test", () => {
  const playbookConfig = {
    id: 13,
    name: "test",
    description: "playbook: test",
    type: ["domain"],
    analyzers: ["TEST_ANALYZER"],
    connectors: ["TEST_CONNECTOR"],
    pivots: [],
    visualizers: [],
    runtime_configuration: {
      pivots: {},
      analyzers: {
        TEST_ANALYZER: {
          query_type: "A",
        },
      },
      connectors: {},
      visualizers: {},
    },
    scan_mode: 2,
    scan_check_time: "0:24:00:00",
    tags: [],
    tlp: "GREEN",
    weight: 0,
    is_editable: true,
    for_organization: true,
    disabled: false,
    starting: true,
    owner: "marti",
    orgPluginDisabled: false,
    plugin_type: "playbook",
  };

  test("form fields", async () => {
    render(
      <BrowserRouter>
        <PlaybookConfigForm
          playbookConfig={playbookConfig}
          toggle={jest.fn()}
          isOpen
          pluginsLoading={false}
        />
      </BrowserRouter>,
    );

    // form fields
    const nameInputField = screen.getByLabelText("Name:");
    expect(nameInputField).toBeInTheDocument();
    expect(nameInputField).toHaveValue("test");

    const descriptionInputField = screen.getByLabelText("Description:");
    expect(descriptionInputField).toBeInTheDocument();
    expect(descriptionInputField).toHaveValue("playbook: test");

    const typeInputField = screen.getByText("Supported types:");
    expect(typeInputField).toBeInTheDocument();
    const ipCheckbox = screen.getAllByRole("checkbox")[0];
    expect(ipCheckbox).not.toBeChecked();
    const urlCheckbox = screen.getAllByRole("checkbox")[1];
    expect(urlCheckbox).not.toBeChecked();
    const domainCheckbox = screen.getAllByRole("checkbox")[2];
    expect(domainCheckbox).toBeChecked();
    const hashCheckbox = screen.getAllByRole("checkbox")[3];
    expect(hashCheckbox).not.toBeChecked();
    const genericCheckbox = screen.getAllByRole("checkbox")[4];
    expect(genericCheckbox).not.toBeChecked();
    const fileCheckbox = screen.getAllByRole("checkbox")[5];
    expect(fileCheckbox).not.toBeChecked();

    const analyzersInputField = screen.getByText("Analyzers:");
    expect(analyzersInputField).toBeInTheDocument();
    expect(screen.getAllByText("TEST_ANALYZER")[0]).toBeInTheDocument();
    const connectorsInputField = screen.getByText("Connectors:");
    expect(connectorsInputField).toBeInTheDocument();
    expect(screen.getAllByText("TEST_CONNECTOR")[0]).toBeInTheDocument();
    const pivotsInputField = screen.getByText("Pivots:");
    expect(pivotsInputField).toBeInTheDocument();
    const visualizersInputField = screen.getByText("Visualizers:");
    expect(visualizersInputField).toBeInTheDocument();

    const tlpInputField = screen.getByText("TLP");
    expect(tlpInputField).toBeInTheDocument();
    const greenTLP = screen.getByRole("radio", { name: "GREEN" });
    expect(greenTLP).toBeInTheDocument();
    expect(greenTLP).toBeChecked();

    const tagsInputField = screen.getByText("Tags:");
    expect(tagsInputField).toBeInTheDocument();

    const scanConfigInputField = screen.getByText("Scan Configuration:");
    expect(scanConfigInputField).toBeInTheDocument();
    const newAnalysisRadio = screen.getByRole("radio", {
      name: "Do not execute if a similar analysis is currently running or reported without fails",
    });
    expect(newAnalysisRadio).toBeInTheDocument();

    const runtimeConfigInputField = screen.getByText("Runtime Configuration:");
    expect(runtimeConfigInputField).toBeInTheDocument();
    const runtimeConfigModalWarning = screen.getByText(
      "Note: Edit this only if you know what you are doing!",
    );
    expect(runtimeConfigModalWarning).toBeInTheDocument();
    const editableRuntimeConfigSection =
      runtimeConfigModalWarning.closest("div");
    const editableRuntimeConfig = editableRuntimeConfigSection.querySelector(
      "#jsonAceEditor__runtime_configuration",
    );
    expect(editableRuntimeConfig).toBeInTheDocument();

    const saveButton = screen.getByRole("button", { name: "Save" });
    expect(saveButton).toBeInTheDocument();
    expect(saveButton.className).toContain("disabled");
  });

  test("edit playbook config", async () => {
    const userAction = userEvent.setup();
    axios.patch.mockImplementation(() => Promise.resolve({ status: 200 }));

    render(
      <BrowserRouter>
        <PlaybookConfigForm
          playbookConfig={playbookConfig}
          toggle={jest.fn()}
          pluginsLoading={false}
          isEditing
        />
      </BrowserRouter>,
    );

    // form fields
    const nameInputField = screen.getByLabelText("Name:");
    expect(nameInputField).toBeInTheDocument();
    expect(nameInputField).toHaveValue("test");

    const descriptionInputField = screen.getByLabelText("Description:");
    expect(descriptionInputField).toBeInTheDocument();
    expect(descriptionInputField).toHaveValue("playbook: test");

    const typeInputField = screen.getByText("Supported types:");
    expect(typeInputField).toBeInTheDocument();
    const ipCheckbox = screen.getAllByRole("checkbox")[0];
    expect(ipCheckbox).not.toBeChecked();
    const urlCheckbox = screen.getAllByRole("checkbox")[1];
    expect(urlCheckbox).not.toBeChecked();
    const domainCheckbox = screen.getAllByRole("checkbox")[2];
    expect(domainCheckbox).toBeChecked();
    const hashCheckbox = screen.getAllByRole("checkbox")[3];
    expect(hashCheckbox).not.toBeChecked();
    const genericCheckbox = screen.getAllByRole("checkbox")[4];
    expect(genericCheckbox).not.toBeChecked();
    const fileCheckbox = screen.getAllByRole("checkbox")[5];
    expect(fileCheckbox).not.toBeChecked();

    const analyzersInputField = screen.getByText("Analyzers:");
    expect(analyzersInputField).toBeInTheDocument();
    expect(screen.getAllByText("TEST_ANALYZER")[0]).toBeInTheDocument();
    const connectorsInputField = screen.getByText("Connectors:");
    expect(connectorsInputField).toBeInTheDocument();
    expect(screen.getAllByText("TEST_CONNECTOR")[0]).toBeInTheDocument();
    const pivotsInputField = screen.getByText("Pivots:");
    expect(pivotsInputField).toBeInTheDocument();
    const visualizersInputField = screen.getByText("Visualizers:");
    expect(visualizersInputField).toBeInTheDocument();

    const tlpInputField = screen.getByText("TLP");
    expect(tlpInputField).toBeInTheDocument();
    const greenTLP = screen.getByRole("radio", { name: "GREEN" });
    expect(greenTLP).toBeInTheDocument();
    expect(greenTLP).toBeChecked();

    const tagsInputField = screen.getByText("Tags:");
    expect(tagsInputField).toBeInTheDocument();

    const scanConfigInputField = screen.getByText("Scan Configuration:");
    expect(scanConfigInputField).toBeInTheDocument();
    const newAnalysisRadio = screen.getByRole("radio", {
      name: "Do not execute if a similar analysis is currently running or reported without fails",
    });
    expect(newAnalysisRadio).toBeInTheDocument();

    const runtimeConfigInputField = screen.getByText("Runtime Configuration:");
    expect(runtimeConfigInputField).toBeInTheDocument();
    const runtimeConfigModalWarning = screen.getByText(
      "Note: Edit this only if you know what you are doing!",
    );
    expect(runtimeConfigModalWarning).toBeInTheDocument();
    const editableRuntimeConfigSection =
      runtimeConfigModalWarning.closest("div");
    const editableRuntimeConfig = editableRuntimeConfigSection.querySelector(
      "#jsonAceEditor__runtime_configuration",
    );
    expect(editableRuntimeConfig).toBeInTheDocument();
    
    const saveButton = screen.getByRole("button", { name: "Save" });
    expect(saveButton).toBeInTheDocument();
    expect(saveButton.className).toContain("disabled");

    // clear editor and type new playbook name
    await userAction.clear(nameInputField);
    await userAction.type(nameInputField, "myNewPlaybook");

    // add ip in supported types
    await userAction.click(ipCheckbox);

    expect(saveButton.className).not.toContain("disabled");
    await userAction.click(saveButton);

    await waitFor(() => {
      expect(axios.patch).toHaveBeenCalledWith(`${PLAYBOOKS_CONFIG_URI}/test`, {
        name: "myNewPlaybook",
        description: "playbook: test",
        type: ["domain", "ip"],
        analyzers: ["TEST_ANALYZER"],
        connectors: ["TEST_CONNECTOR"],
        visualizers: [],
        pivots: [],
        runtime_configuration: {
          pivots: {},
          analyzers: { TEST_ANALYZER: { query_type: "A" } },
          connectors: {},
          visualizers: {},
        },
        tags_labels: [],
        tlp: "GREEN",
        scan_mode: 2,
        scan_check_time: "24:00:00",
      });
    });
  });

  test("create playbook config", async () => {
    const userAction = userEvent.setup();
    axios.post.mockImplementation(() => Promise.resolve({ status: 201 }));

    render(
      <BrowserRouter>
        <PlaybookConfigForm toggle={jest.fn()} pluginsLoading={false} />
      </BrowserRouter>,
    );

    // form fields
    const nameInputField = screen.getByLabelText("Name:");
    expect(nameInputField).toBeInTheDocument();

    const descriptionInputField = screen.getByLabelText("Description:");
    expect(descriptionInputField).toBeInTheDocument();

    const typeInputField = screen.getByText("Supported types:");
    expect(typeInputField).toBeInTheDocument();
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
    const fileCheckbox = screen.getAllByRole("checkbox")[5];
    expect(fileCheckbox).not.toBeChecked();

    const analyzersInputField = screen.getByText("Analyzers:");
    expect(analyzersInputField).toBeInTheDocument();
    const connectorsInputField = screen.getByText("Connectors:");
    expect(connectorsInputField).toBeInTheDocument();
    const pivotsInputField = screen.getByText("Pivots:");
    expect(pivotsInputField).toBeInTheDocument();
    const visualizersInputField = screen.getByText("Visualizers:");
    expect(visualizersInputField).toBeInTheDocument();

    const tlpInputField = screen.getByText("TLP");
    expect(tlpInputField).toBeInTheDocument();
    const amberTLP = screen.getByRole("radio", { name: "AMBER" });
    expect(amberTLP).toBeInTheDocument();
    expect(amberTLP).toBeChecked();

    const tagsInputField = screen.getByText("Tags:");
    expect(tagsInputField).toBeInTheDocument();

    const scanConfigInputField = screen.getByText("Scan Configuration:");
    expect(scanConfigInputField).toBeInTheDocument();
    const newAnalysisRadio = screen.getByRole("radio", {
      name: "Do not execute if a similar analysis is currently running or reported without fails",
    });
    expect(newAnalysisRadio).toBeInTheDocument();

    const runtimeConfigInputField = screen.getByText("Runtime Configuration:");
    expect(runtimeConfigInputField).toBeInTheDocument();
    const runtimeConfigModalWarning = screen.getByText(
      "Note: Edit this only if you know what you are doing!",
    );
    expect(runtimeConfigModalWarning).toBeInTheDocument();
    const editableRuntimeConfigSection =
      runtimeConfigModalWarning.closest("div");
    const editableRuntimeConfig = editableRuntimeConfigSection.querySelector(
     "#jsonAceEditor__runtime_configuration",
    );
    expect(editableRuntimeConfig).toBeInTheDocument();

    const saveButton = screen.getByRole("button", { name: "Save" });
    expect(saveButton).toBeInTheDocument();
    expect(saveButton.className).toContain("disabled");

    // clear editor and type new playbook name
    await userAction.clear(nameInputField);
    await userAction.type(nameInputField, "myNewPlaybook");

    // clear editor and type new description
    await userAction.clear(descriptionInputField);
    await userAction.type(descriptionInputField, "myNewPlaybook description");

    // add ip in supported types
    await userAction.click(ipCheckbox);

    // select the test analyzer
    /* the id change in case you run a single test or all of them.
      we need this strange way to access instead of the id */
    const analyzerDropdownButton = screen.getAllByRole("combobox")[0];
    expect(analyzerDropdownButton).toBeInTheDocument();
    await userAction.click(analyzerDropdownButton);

    const testAnalyzerButton = screen.getAllByRole("option")[0];
    expect(testAnalyzerButton).toBeInTheDocument();
    await userAction.click(testAnalyzerButton);

    userAction.click(saveButton);

    await waitFor(() => {
      expect(axios.post).toHaveBeenCalledWith(`${PLAYBOOKS_CONFIG_URI}`, {
        name: "myNewPlaybook",
        description: "myNewPlaybook description",
        type: ["ip"],
        analyzers: ["TEST_ANALYZER"],
        connectors: [],
        visualizers: [],
        pivots: [],
        runtime_configuration: {
          pivots: {},
          analyzers: {},
          connectors: {},
          visualizers: {},
        },
        tags_labels: [],
        tlp: "AMBER",
        scan_mode: 2,
        scan_check_time: "24:00:00",
      });
    });
  });
});
