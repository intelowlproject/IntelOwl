import React from "react";
import "@testing-library/jest-dom";
import axios from "axios";
import { screen, render } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
// import { API_BASE_URI } from "../../../../src/constants/apiURLs";
import { PivotConfigForm } from "../../../../src/components/plugins/types/PivotConfigForm";

jest.mock("axios");

describe("PivotConfigForm test", () => {
  test("form fields", async () => {
    render(
      <BrowserRouter>
        <PivotConfigForm
          playbookConfig={{}}
          toggle={jest.fn()}
        />
      </BrowserRouter>,
    );

    // form fields
    const nameInputField = screen.getByLabelText("Name:");
    expect(nameInputField).toBeInTheDocument();

    const pythonModuleInputField = screen.getByText("Python Module:");
    expect(pythonModuleInputField).toBeInTheDocument();

    const playbookInputField = screen.getByText("Playbook to Execute:");
    expect(playbookInputField).toBeInTheDocument();

    const saveButton = screen.getByRole("button", { name: "Save" });
    expect(saveButton).toBeInTheDocument();
    expect(saveButton.className).toContain("disabled");
  });

  test("create pivot config", async () => {
    const userAction = userEvent.setup();
    axios.post.mockImplementation(() => Promise.resolve({ status: 201 }));

    render(
      <BrowserRouter>
        <PivotConfigForm
          playbookConfig={{}}
          toggle={jest.fn()}
        />
      </BrowserRouter>,
    );

    // form fields
    const nameInputField = screen.getByLabelText("Name:");
    expect(nameInputField).toBeInTheDocument();

    const pythonModuleInputField = screen.getByText("Python Module:");
    expect(pythonModuleInputField).toBeInTheDocument();

    const playbookInputField = screen.getByText("Playbook to Execute:");
    expect(playbookInputField).toBeInTheDocument();

    const saveButton = screen.getByRole("button", { name: "Save" });
    expect(saveButton).toBeInTheDocument();
    expect(saveButton.className).toContain("disabled");

    // clear editor and type new playbook name
    await userAction.clear(nameInputField);
    await userAction.type(nameInputField, "myNewPivot");

    // expect(saveButton.className).not.toContain("disabled");
    // await userAction.click(saveButton);

    // await waitFor(() => {
    //   expect(axios.post).toHaveBeenCalledWith(`${API_BASE_URI}/pivot`, {
    //     name: "myNewPlaybook",
    //     description: "playbook: test",
    //     related_analyzers: ["TEST_ANALYZER"],
    //     related_connectors: ["TEST_CONNECTOR"],
    //     soft_time_limit: 2,
    //   });
    // });
  });
});
