import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import { RuntimeConfigurationModal } from "../../../../src/components/scan/utils/RuntimeConfigurationModal";
import { mockedUsePluginConfigurationStore } from "../../../mock";

jest.mock("../../../../src/stores/usePluginConfigurationStore", () => ({
  usePluginConfigurationStore: jest.fn((state) =>
    state(mockedUsePluginConfigurationStore),
  ),
}));

describe("Runtime Configuration Modal test", () => {
  test("Runtime Configuration Modal - playbook", () => {
    const formik = {
      values: {
        observableType: "observable",
        classification: "domain",
        observable_names: ["google.com"],
        files: [],
        analyzers: [],
        connectors: [],
        playbook: {
          isDisabled: false,
          value: "Dns",
          analyzers: ["TEST_ANALYZER"],
          connectors: [],
          label: {},
          labelDisplay: "Dns",
          tags: [],
          tlp: "AMBER",
          scan_mode: "2",
          scan_check_time: "1:00:00:00",
          runtime_configuration: {
            pivots: {},
            analyzers: {},
            connectors: {},
            visualizers: {},
          },
        },
        tlp: "AMBER",
        runtime_configuration: {
          pivots: {},
          analyzers: {},
          connectors: {},
          visualizers: {},
        },
        tags: [],
        scan_mode: "2",
        analysisOptionValues: "Playbooks",
        scan_check_time: 24,
      },
    };

    render(
      <BrowserRouter>
        <RuntimeConfigurationModal
          isOpen
          toggle={() => jest.fn()}
          formik={formik}
        />
      </BrowserRouter>,
    );

    const runtimeConfigModalTitle = screen.getByText(
      "Edit Runtime Configuration",
    );
    expect(runtimeConfigModalTitle).toBeInTheDocument();
    expect(runtimeConfigModalTitle.closest("div").className).toContain(
      "modal-header",
    );
    const runtimeConfigModalWarning = screen.getByText(
      "Note: Edit this only if you know what you are doing!",
    );
    expect(runtimeConfigModalWarning).toBeInTheDocument();
    // editable text area
    const editableRuntimeConfigSection =
      runtimeConfigModalWarning.closest("div");
    const editableRuntimeConfig = editableRuntimeConfigSection.querySelector(
      "#edit_runtime_configuration-modal",
    );
    expect(editableRuntimeConfig).toBeInTheDocument();
    const editableText = screen.getAllByText("TEST_ANALYZER")[0];
    expect(editableText).toBeInTheDocument();
    expect(editableRuntimeConfig.textContent).toBe(
      "{  analyzers: {    TEST_ANALYZER: {      query_type: 'AAAA'    }  },  connectors: {},  pivots: {},  visualizers: {}}",
    );
    // buttons
    const closeButton = screen.getByRole("button", {
      name: "Close",
    });
    expect(closeButton).toBeInTheDocument();
    const ignoreButton = screen.getByRole("button", {
      name: "Ignore changes & close",
    });
    expect(ignoreButton).toBeInTheDocument();
    const saveButton = screen.getByRole("button", {
      name: "Save & Close",
    });
    expect(saveButton).toBeInTheDocument();
    // side section with descriptions
    const analyzersTitle = screen.getByRole("heading", {
      name: "ANALYZERS:",
    });
    expect(analyzersTitle).toBeInTheDocument();
    const connectorsTitle = screen.getByRole("heading", {
      name: "CONNECTORS: null",
    });
    expect(connectorsTitle).toBeInTheDocument();
    const pivotsTitle = screen.getByRole("heading", {
      name: "PIVOTS: null",
    });
    expect(pivotsTitle).toBeInTheDocument();
    const visualizersTitle = screen.getByRole("heading", {
      name: "VISUALIZERS: null",
    });
    expect(visualizersTitle).toBeInTheDocument();
    const analyzersConfigTitle = screen.getByRole("heading", {
      name: "TEST_ANALYZER",
    });
    expect(analyzersConfigTitle).toBeInTheDocument();
    expect(
      screen.getByText("Test analyzer param description."),
    ).toBeInTheDocument();
  });

  test("Runtime Configuration Modal - analyzer", () => {
    const formik = {
      values: {
        observableType: "observable",
        classification: "domain",
        observable_names: ["google.com"],
        files: [],
        analyzers: [
          {
            value: "TEST_ANALYZER",
            isDisabled: false,
            labelDisplay: "TEST_ANALYZER",
            label: {},
          },
        ],
        connectors: [],
        playbook: "",
        tlp: "AMBER",
        runtime_configuration: {},
        tags: [],
        scan_mode: "2",
        analysisOptionValues: "Analyzers/Connectors",
        scan_check_time: 24,
      },
    };

    render(
      <BrowserRouter>
        <RuntimeConfigurationModal
          isOpen
          toggle={() => jest.fn()}
          formik={formik}
        />
      </BrowserRouter>,
    );

    const runtimeConfigModalTitle = screen.getByText(
      "Edit Runtime Configuration",
    );
    expect(runtimeConfigModalTitle).toBeInTheDocument();
    expect(runtimeConfigModalTitle.closest("div").className).toContain(
      "modal-header",
    );
    const runtimeConfigModalWarning = screen.getByText(
      "Note: Edit this only if you know what you are doing!",
    );
    expect(runtimeConfigModalWarning).toBeInTheDocument();
    // editable text area
    const editableRuntimeConfigSection =
      runtimeConfigModalWarning.closest("div");
    const editableRuntimeConfig = editableRuntimeConfigSection.querySelector(
      "#edit_runtime_configuration-modal",
    );
    expect(editableRuntimeConfig).toBeInTheDocument();
    const editableText = screen.getAllByText("TEST_ANALYZER")[0];
    expect(editableText).toBeInTheDocument();
    expect(editableRuntimeConfig.textContent).toBe(
      "{  analyzers: {    TEST_ANALYZER: {      query_type: 'AAAA'    }  },  connectors: {}}",
    );
    // buttons
    const closeButton = screen.getByRole("button", {
      name: "Close",
    });
    expect(closeButton).toBeInTheDocument();
    const ignoreButton = screen.getByRole("button", {
      name: "Ignore changes & close",
    });
    expect(ignoreButton).toBeInTheDocument();
    const saveButton = screen.getByRole("button", {
      name: "Save & Close",
    });
    expect(saveButton).toBeInTheDocument();
    // side section with descriptions
    const analyzersTitle = screen.getByRole("heading", {
      name: "ANALYZERS:",
    });
    expect(analyzersTitle).toBeInTheDocument();
    const analyzersConfigTitle = screen.getByRole("heading", {
      name: "TEST_ANALYZER",
    });
    expect(analyzersConfigTitle).toBeInTheDocument();
    expect(
      screen.getByText("Test analyzer param description."),
    ).toBeInTheDocument();
  });
});
