import React from "react";
import axios from "axios";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import Analyzable from "../../../src/components/analyzables/Analyzables";
import { ANALYZABLES_URI } from "../../../src/constants/apiURLs";

jest.mock("axios");

describe("test Analyzable component", () => {
  test("Analyzable page - fields", async () => {
    const {container} = render(
      <BrowserRouter>
        <Analyzable />
      </BrowserRouter>,
    );

    const analyzableTitle = screen.getByRole("heading", { name: /Analyzables/i });
    expect(analyzableTitle).toBeInTheDocument();

    const inputField = screen.getByRole("textbox");
    expect(inputField).toBeInTheDocument();
    expect(inputField.id).toBe("analyzable-0");
    const deleteButton = container.querySelector(`#analyzable-0-deletebtn`);
    expect(deleteButton).toBeInTheDocument();
    expect(deleteButton.className).toContain("disabled");
    const addButton = container.querySelector(`#analyzable-0-addbtn`);
    expect(addButton).toBeInTheDocument();
    expect(addButton.className).not.toContain("disabled");

    const multipleInputButton = screen.getByRole("button", { name: /Load multiple analyzables/i });
    expect(multipleInputButton).toBeInTheDocument();

    // search button
    const searchButton = screen.getByRole("button", { name: /Search/i });
    expect(searchButton).toBeInTheDocument();
    expect(searchButton.className).toContain("disabled");

    // column headers
    expect(
      screen.getByRole("columnheader", { name: "ID" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: "Name" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: "Discovery date" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: "SHA 256" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: "Classification All" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: "Last Analysis" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: "Last Evaluation" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("columnheader", { name: "Tags" }),
      ).toBeInTheDocument();
    expect(
        screen.getByRole("columnheader", { name: "Playbook" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("columnheader", { name: "Actions" }),
    ).toBeInTheDocument();

    // no data
    expect(screen.getByRole("cell", { name: "No Data" })).toBeInTheDocument();
  });

  test("Analyzable page - search single analyzable", async () => {
    const user = userEvent.setup();
    axios.post.mockImplementation(() =>
      Promise.resolve({
        status: 200,
        data: [
            {
                    id: 1,
                    jobs: [
                        1,
                        4,
                        5
                    ],
                    name: "google.com",
                    discovery_date: "2025-05-05T12:55:43.777042Z",
                    md5: "1d5920f4b44b27a802bd77c4f0536f5a",
                    sha256: "d4c9d9027326271a89ce51fcaf328ed673f17be33469ff979e8ab8dd501e664f",
                    sha1: "baea954b95731c68ae6e45bd1e252eb4560cdc45",
                    classification: "domain",
                    mimetype: null,
                    file: null,
                    last_reliability: 8,
                    last_evaluation: "trusted",
                    last_analysis: "2025-05-14T10:55:16.706478Z",
                    tags: null,
                    playbook_to_execute: "Dns"
            },
        ]
      }),
    );

    const {container} = render(
      <BrowserRouter>
        <Analyzable />
      </BrowserRouter>,
    );

    const analyzableTitle = screen.getByRole("heading", { name: /Analyzables/i });
    expect(analyzableTitle).toBeInTheDocument();

    const inputField = screen.getByRole("textbox");
    expect(inputField).toBeInTheDocument();
    expect(inputField.id).toBe("analyzable-0");
    const deleteButton = container.querySelector(`#analyzable-0-deletebtn`);
    expect(deleteButton).toBeInTheDocument();
    expect(deleteButton.className).toContain("disabled");
    const addButton = container.querySelector(`#analyzable-0-addbtn`);
    expect(addButton).toBeInTheDocument();
    expect(addButton.className).not.toContain("disabled");


    const multipleInputButton = screen.getByRole("button", { name: /Load multiple analyzables/i });
    expect(multipleInputButton).toBeInTheDocument();

    // search button
    const searchButton = screen.getByRole("button", { name: /Search/i });
    expect(searchButton).toBeInTheDocument();
    expect(searchButton.className).toContain("disabled");

   // column headers
   expect(
        screen.getByRole("columnheader", { name: "ID" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("columnheader", { name: "Name" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("columnheader", { name: "Discovery date" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("columnheader", { name: "SHA 256" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("columnheader", { name: "Classification All" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("columnheader", { name: "Last Analysis" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("columnheader", { name: "Last Evaluation" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("columnheader", { name: "Tags" }),
        ).toBeInTheDocument();
    expect(
        screen.getByRole("columnheader", { name: "Playbook" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("columnheader", { name: "Actions" }),
    ).toBeInTheDocument();
    // no data
    expect(screen.getByRole("cell", { name: "No Data" })).toBeInTheDocument();

    await user.type(inputField, "google.com");
    expect(deleteButton.className).toContain("disabled");
    expect(searchButton.className).not.toContain("disabled");
    await user.click(searchButton);

    await waitFor(() => {
      expect(axios.post).toHaveBeenCalledWith(`${ANALYZABLES_URI}/get_analyzables`, ["google.com"]);
      expect(screen.getByText("#1")).toBeInTheDocument();
      expect(screen.getByText("google.com")).toBeInTheDocument();
      expect(screen.getByText("Dns")).toBeInTheDocument();
      expect(screen.getAllByText("domain")[1]).toBeInTheDocument();
      expect(screen.getByText("TRUSTED")).toBeInTheDocument();
    });
  });

  test("Analyzable page - search multiple analyzable", async () => {
    const user = userEvent.setup();
    axios.post.mockImplementation(() =>
      Promise.resolve({
        status: 200,
        data: [
            {
                    id: 1,
                    jobs: [
                        1,
                        4,
                        5
                    ],
                    name: "google.com",
                    discovery_date: "2025-05-05T12:55:43.777042Z",
                    md5: "1d5920f4b44b27a802bd77c4f0536f5a",
                    sha256: "d4c9d9027326271a89ce51fcaf328ed673f17be33469ff979e8ab8dd501e664f",
                    sha1: "baea954b95731c68ae6e45bd1e252eb4560cdc45",
                    classification: "domain",
                    mimetype: null,
                    file: null,
                    last_reliability: 8,
                    last_evaluation: "trusted",
                    last_analysis: "2025-05-14T10:55:16.706478Z",
                    tags: null,
                    playbook_to_execute: "Dns"
            },
            {
                name: "8.8.8.8",
                tags: ["not found"]
            }
        ]
      }),
    );

    const { container } = render(
      <BrowserRouter>
        <Analyzable />
      </BrowserRouter>,
    );

    const analyzableTitle = screen.getByRole("heading", { name: /Analyzables/i });
    expect(analyzableTitle).toBeInTheDocument();

    const inputField = screen.getByRole("textbox");
    expect(inputField).toBeInTheDocument();
    expect(inputField.id).toBe("analyzable-0");
    const deleteButton = container.querySelector(`#analyzable-0-deletebtn`);
    expect(deleteButton).toBeInTheDocument();
    expect(deleteButton.className).toContain("disabled");
    const addButton = container.querySelector(`#analyzable-0-addbtn`);
    expect(addButton).toBeInTheDocument();
    expect(addButton.className).not.toContain("disabled");

    const multipleInputButton = screen.getByRole("button", { name: /Load multiple analyzables/i });
    expect(multipleInputButton).toBeInTheDocument();

    // search button
    const searchButton = screen.getByRole("button", { name: /Search/i });
    expect(searchButton).toBeInTheDocument();
    expect(searchButton.className).toContain("disabled");

   // column headers
   expect(
        screen.getByRole("columnheader", { name: "ID" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("columnheader", { name: "Name" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("columnheader", { name: "Discovery date" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("columnheader", { name: "SHA 256" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("columnheader", { name: "Classification All" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("columnheader", { name: "Last Analysis" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("columnheader", { name: "Last Evaluation" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("columnheader", { name: "Tags" }),
        ).toBeInTheDocument();
    expect(
        screen.getByRole("columnheader", { name: "Playbook" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("columnheader", { name: "Actions" }),
    ).toBeInTheDocument();
    // no data
    expect(screen.getByRole("cell", { name: "No Data" })).toBeInTheDocument();

    await user.type(inputField, "google.com");
    expect(deleteButton.className).toContain("disabled");
    
    await user.click(addButton);
    expect(deleteButton.className).not.toContain("disabled");

    const secondInputField = screen.getAllByRole("textbox")[1];
    expect(secondInputField).toBeInTheDocument();
    expect(secondInputField.id).toBe("analyzable-1");
    const secondDeleteButton = container.querySelector(`#analyzable-1-deletebtn`);
    expect(secondDeleteButton).toBeInTheDocument();
    expect(secondDeleteButton.className).not.toContain("disabled");
    const secondAddButton = container.querySelector(`#analyzable-1-addbtn`);
    expect(secondAddButton).toBeInTheDocument();
    expect(secondAddButton.className).not.toContain("disabled");

    await user.type(secondInputField, "8.8.8.8");

    expect(searchButton.className).not.toContain("disabled");
    await user.click(searchButton);

    await waitFor(() => {
      expect(axios.post).toHaveBeenCalledWith(`${ANALYZABLES_URI}/get_analyzables`, ["google.com", "8.8.8.8"]);
      // first row
      expect(screen.getByText("#1")).toBeInTheDocument();
      expect(screen.getByText("google.com")).toBeInTheDocument();
      expect(screen.getByText("Dns")).toBeInTheDocument();
      expect(screen.getAllByText("domain")[1]).toBeInTheDocument();
      expect(screen.getByText("TRUSTED")).toBeInTheDocument();
      // second row
      expect(screen.getByText("NF")).toBeInTheDocument();
      expect(screen.getByText("Not Found")).toBeInTheDocument();
    });
  });
});
