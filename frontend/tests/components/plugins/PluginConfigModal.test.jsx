import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import { PluginConfigModal } from "../../../src/components/plugins/PluginConfigModal";
import { mockedPlugins } from "../../mock";

/*
    default: edit generic plugin config
    case A: create basic analyzer
    case B: edit basic analyzer
    case D: create basic pivot
    case E: edit basic pivot
*/

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

describe("test PluginConfigModal component", () => {
  test("plugins config modal - default plugin config", () => {
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

  test("plugins config modal - case A: create basic analyzer", () => {
    render(
      <BrowserRouter>
        <PluginConfigModal
          pluginConfig={{}}
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
    expect(screen.getByText("Create a new analyzer")).toBeInTheDocument();
    // expect AnalyzerConfigForm is called
    const AnalyzerConfigForm = document.querySelector("#analyzer-config-form");
    expect(AnalyzerConfigForm).toBeInTheDocument();
  });

  test("plugins config modal - case B: edit basic analyzer", () => {
    const basicAnalyzer = mockedPlugins.ANALYZER;
    basicAnalyzer.python_module =
      "basic_observable_analyzer.BasicObservableAnalyzer";
    render(
      <BrowserRouter>
        <PluginConfigModal
          pluginConfig={basicAnalyzer}
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
    expect(screen.getByText("Edit analyzer config")).toBeInTheDocument();
    // expect AnalyzerConfigForm is called
    const AnalyzerConfigForm = document.querySelector("#analyzer-config-form");
    expect(AnalyzerConfigForm).toBeInTheDocument();
  });

  test("plugins config modal - case D: create basic pivot", () => {
    render(
      <BrowserRouter>
        <PluginConfigModal
          pluginConfig={{}}
          pluginType="pivot"
          toggle={() => jest.fn()}
          isOpen
        />
      </BrowserRouter>,
    );
    // modal
    const pluginConfigModal = document.querySelector("#plugin-config-modal");
    expect(pluginConfigModal).toBeInTheDocument();
    // modal title
    expect(screen.getByText("Create a new pivot")).toBeInTheDocument();
    // expect PivotConfigForm is called
    const PivotConfigForm = document.querySelector("#pivot-config-form");
    expect(PivotConfigForm).toBeInTheDocument();
  });

  test("plugins config modal - case E: edit basic pivot", () => {
    render(
      <BrowserRouter>
        <PluginConfigModal
          pluginConfig={mockedPlugins.PIVOT}
          pluginType="pivot"
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
    // expect PivotConfigForm is called
    const PivotConfigForm = document.querySelector("#pivot-config-form");
    expect(PivotConfigForm).toBeInTheDocument();
  });
});
