import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
// import { MultipleObservablesModal } from "../../../../src/components/scan/utils/MultipleObservablesModal";
import { MultipleInputModal } from "../../../src/components/common/form/MultipleInputModal";

describe("Multiple Observable Modal test", () => {
  test("Multiple Observable Modal", async () => {
    const user = userEvent.setup();

    const formik = {
      values: {
        observableType: "observable",
        classification: "",
        observable_names: [],
        files: [],
        analyzers: [],
        connectors: [],
        playbook: {},
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
        <MultipleInputModal
          isOpen
          toggle={() => jest.fn()}
          formik={formik}
          formikSetField=""
        />
      </BrowserRouter>,
    );

    const modalTitle = screen.getByText("Load Multiple Values");
    expect(modalTitle).toBeInTheDocument();
    expect(modalTitle.closest("div").className).toContain("modal-header");
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
    // button
    const extractButton = screen.getByRole("button", {
      name: "Extract",
    });
    expect(extractButton).toBeInTheDocument();
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
  });
});
