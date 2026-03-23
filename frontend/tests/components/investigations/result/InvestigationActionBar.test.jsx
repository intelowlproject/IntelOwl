import React from "react";
import axios from "axios";
import "@testing-library/jest-dom";
import { render, waitFor, screen } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import { InvestigationActionsBar } from "../../../../src/components/investigations/result/InvestigationActionBar";
import { INVESTIGATION_BASE_URI } from "../../../../src/constants/apiURLs";

jest.mock("axios");

describe("test InvestigationActionsBar", () => {
  test("delete button", async () => {
    axios.delete.mockImplementation(() => Promise.resolve({ status: 204 }));

    const { container } = render(
      <BrowserRouter>
        <InvestigationActionsBar
          investigation={{
            id: 1,
            name: "My test",
            jobs: [1, 2],
            total_jobs: 2,
            description: "test description",
            status: "concluded",
            start_time: "2024-05-06T08:19:03.256003",
            end_time: "2024-05-06T08:19:04.484684",
            tags: [null],
          }}
        />
      </BrowserRouter>,
    );
    const user = userEvent.setup();
    const actionMenuButton = container.querySelector("#investigationActions");
    expect(actionMenuButton).toBeInTheDocument();
    await user.click(actionMenuButton);

    const deleteButton = screen.getByRole("menuitem", {
      name: "Delete investigation",
    });
    await user.click(deleteButton);
    // confirm dialog
    const confirmButton = screen.getByRole("button", {
      name: "Ok",
    });
    await user.click(confirmButton);

    await waitFor(() => {
      expect(axios.delete.mock.calls.length).toBe(1);
      expect(axios.delete).toHaveBeenCalledWith(`${INVESTIGATION_BASE_URI}/1`);
    });
  });
});
