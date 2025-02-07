import React from "react";
import "@testing-library/jest-dom";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import { format } from "date-fns";
import { TimePicker } from "../../../src/components/common/TimePicker";
import { datetimeFormatStr } from "../../../src/constants/miscConst";

describe("test TimePicker component", () => {
  test("time picker", async () => {
    const toDate = new Date();
    const fromDate = structuredClone(toDate);
    fromDate.setDate(fromDate.getDate() - 1);
    const toDateValue = format(toDate, datetimeFormatStr);
    const fromDateValue = format(fromDate, datetimeFormatStr);

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
    // datetime saves also milliseconds
    expect(firstDateInput).toHaveValue(`${fromDateValue  }.000`);
    expect(secondDateInput).toHaveValue(`${toDateValue  }.000`);

    /* datetime-local input is editable only with fireEvent, user.type doesn't work:
    https://github.com/testing-library/user-event/issues/399#issuecomment-656084165 */
    await fireEvent.change(firstDateInput, {
      target: { value: "2024-02-05T12:06:01" },
    });
    await fireEvent.change(secondDateInput, {
      target: { value: "2024-05-13T12:06:01" },
    });

    await waitFor(() => {
      expect(firstDateInput).toHaveValue("2024-02-05T12:06:01.000");
      expect(secondDateInput).toHaveValue("2024-05-13T12:06:01.000");
    });
  });
});
