import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import { TimePicker } from "../../../src/components/common/TimePicker";

describe("test TimePicker component", () => {
  test("time picker", async () => {
    const defaultFromDate = new Date();
    defaultFromDate.setDate(defaultFromDate.getDate() - 1);
    const toDateValue = new Date().toISOString().split("T")[0];
    const fromDateValue = defaultFromDate.toISOString().split("T")[0];

    const user = userEvent.setup();
    const { container } = render(
      <BrowserRouter>
        <TimePicker />
      </BrowserRouter>,
    );

    // labels
    const fromLabel = screen.getByText("From:");
    expect(fromLabel).toBeInTheDocument();
    const toLabel = screen.getByText("To:");
    expect(toLabel).toBeInTheDocument();

    // time picker input
    const firstDateInput = container.querySelector("#DatePicker__gte");
    expect(firstDateInput).toBeInTheDocument();
    const secondDateInput = container.querySelector("#DatePicker__lte");
    expect(secondDateInput).toBeInTheDocument();
    expect(firstDateInput).toHaveValue(fromDateValue);
    expect(secondDateInput).toHaveValue(toDateValue);

    // clear the input by highlighting all the current text and then replacing it with the new value
    await user.type(firstDateInput, "2024-02-05", {
      initialSelectionStart: 0,
      initialSelectionEnd: firstDateInput.value.length,
    });
    await user.type(secondDateInput, "2024-05-13", {
      initialSelectionStart: 0,
      initialSelectionEnd: secondDateInput.value.length,
    });
    await waitFor(() => {
      expect(firstDateInput).toHaveValue("2024-02-05");
      expect(secondDateInput).toHaveValue("2024-05-13");
    });
  });
});
