import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import { PluginConfigModal } from "../../../src/components/plugins/PluginConfigModal";
import { mockedPlugins, mockedPlaybooks } from "../../mock";

// mock PluginConfigContainer component
jest.mock("../../../src/components/plugins/PluginConfigContainer", () => ({
  PluginConfigContainer: jest.fn(() => <div id="plugin-config-container" />),
}));
// mock AnalyzerConfigForm component
jest.mock("../../../src/components/plugins/forms/AnalyzerConfigForm", () => ({
  AnalyzerConfigForm: jest.fn(() => <div id="analyzer-config-form" />),
}));
// mock PivotConfigForm component
jest.mock("../../../src/components/plugins/forms/PivotConfigForm", () => ({
  PivotConfigForm: jest.fn(() => <div id="pivot-config-form" />),
}));
// mock PlaybookConfigForm component
jest.mock("../../../src/components/plugins/forms/PlaybookConfigForm", () => ({
  PlaybookConfigForm: jest.fn(() => <div id="playbook-config-form" />),
}));

describe("test PluginConfigModal component", () => {
  test("plugins config modal - case A: default plugin config", () => {
    render(
      <BrowserRouter>
        <PluginConfigModal
          pluginConfig={mockedPlugins.ANALYZER}
          pluginType="analyzer"
          toggle={() => jest.fn()}
          isOpen
        />
      </BrowserRouter>,
    );
    // modal
    const pluginConfigModal = document.querySelector("#plugin-config-modal");
    expect(pluginConfigModal).toBeInTheDocument();
    // modal title
    expect(screen.getByText("Plugin config")).toBeInTheDocument();
    // expect PluginConfigContainer is called
    const pluginConfigContainer = document.querySelector(
      "#plugin-config-container",
    );
    expect(pluginConfigContainer).toBeInTheDocument();
  });

  test.each([
    // case B: create basic analyzer
    {
      pluginType: "analyzer",
      pluginConfig: {},
    },
    // case D: create basic pivot
    {
      pluginType: "pivot",
      pluginConfig: {},
    },
    // case F: create playbook
    {
      pluginType: "playbook",
      pluginConfig: {},
    },
    // case F.1: create playbook - save as a playbook button
    {
      pluginType: "playbook",
      pluginConfig: {
        type: ["domain"],
        runtime_configuration: {
          analyzers: {},
          connectors: {},
          visualizers: {},
        },
        analyzers: [],
        connectors: [],
        pivots: ["TEST_PIVOT"],
        scan_mode: 2,
        scan_check_time: "02:00:00:00",
        tags: [],
        tlp: "CLEAR",
      },
    },
  ])(
    "plugins config modal - Create $pluginType",
    ({ pluginType, pluginConfig }) => {
      render(
        <BrowserRouter>
          <PluginConfigModal
            pluginConfig={pluginConfig}
            pluginType={pluginType}
            toggle={() => jest.fn()}
            isOpen
          />
        </BrowserRouter>,
      );
      // modal
      const pluginConfigModal = document.querySelector("#plugin-config-modal");
      expect(pluginConfigModal).toBeInTheDocument();
      // modal title
      const title = `Create a new ${pluginType}`;
      expect(screen.getByText(title)).toBeInTheDocument();
      // expect correct form is called
      const configForm = document.querySelector(`#${pluginType}-config-form`);
      expect(configForm).toBeInTheDocument();
    },
  );

  test.each([
    // case C: edit basic analyzer
    {
      pluginType: "analyzer",
      pluginConfig: mockedPlugins.ANALYZER,
    },
    // case E: edit basic pivot
    {
      pluginType: "pivot",
      pluginConfig: mockedPlugins.PIVOT,
    },
    // case G: edit playbook
    {
      pluginType: "playbook",
      pluginConfig: mockedPlaybooks.TEST_PLAYBOOK_DOMAIN,
    },
  ])(
    "plugins config modal - Edit $pluginType",
    ({ pluginType, pluginConfig }) => {
      const config = pluginConfig;
      if (pluginType === "analyzer") {
        config.python_module =
          "basic_observable_analyzer.BasicObservableAnalyzer";
      }

      render(
        <BrowserRouter>
          <PluginConfigModal
            pluginConfig={config}
            pluginType={pluginType}
            toggle={() => jest.fn()}
            isOpen
          />
        </BrowserRouter>,
      );
      // modal
      const pluginConfigModal = document.querySelector("#plugin-config-modal");
      expect(pluginConfigModal).toBeInTheDocument();
      // modal title
      const title = `Edit ${pluginType} config`;
      expect(screen.getByText(title)).toBeInTheDocument();
      // expect correct form is called
      const configForm = document.querySelector(`#${pluginType}-config-form`);
      expect(configForm).toBeInTheDocument();
    },
  );
});
