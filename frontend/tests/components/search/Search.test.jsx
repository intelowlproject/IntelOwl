import React from "react";
import axios from "axios";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import { format } from "date-fns";
import ReportsSearch from "../../../src/components/search/ReportsSearch";
import { PLUGIN_REPORT_QUERIES } from "../../../src/constants/apiURLs";

jest.mock("axios");

describe("test Search component", () => {
  test("Search page - fields", async () => {
    render(
      <BrowserRouter>
        <ReportsSearch />
      </BrowserRouter>,
    );

    const searchTitle = screen.getByRole("heading", { name: /Search/i });
    expect(searchTitle).toBeInTheDocument();
    const hitsText = screen.getByText("0 total");
    expect(hitsText).toBeInTheDocument();
    const searchDescription = screen.getByText(
      "Advanced search in plugin reports of the performed analysis.",
    );
    expect(searchDescription).toBeInTheDocument();

    // first row
    const typeField = screen.getByRole("combobox", { name: /Type:/i });
    expect(typeField).toBeInTheDocument();
    const nameField = screen.getByRole("textbox", { name: /Name:/i });
    expect(nameField).toBeInTheDocument();
    const statusField = screen.getByRole("combobox", { name: /Status:/i });
    expect(statusField).toBeInTheDocument();
    // second row
    const startTimeField = screen.getByText("Start time:");
    expect(startTimeField).toBeInTheDocument();
    const fromStartTimeInput = screen.getAllByText("from")[0];
    expect(fromStartTimeInput).toBeInTheDocument();
    const toStartTimeInput = screen.getAllByText("to")[0];
    expect(toStartTimeInput).toBeInTheDocument();
    const endTimeField = screen.getByText("End time:");
    expect(endTimeField).toBeInTheDocument();
    const fromEndTimeInput = screen.getAllByText("from")[1];
    expect(fromEndTimeInput).toBeInTheDocument();
    const toEndTimeInput = screen.getAllByText("to")[1];
    expect(toEndTimeInput).toBeInTheDocument();
    const errorsField = screen.getByRole("combobox", { name: /Errors:/i });
    expect(errorsField).toBeInTheDocument();
    // third row
    const fullTextField = screen.getByRole("textbox", {
      name: /Text search:/i,
    });
    expect(fullTextField).toBeInTheDocument();
    const searchButton = screen.getByRole("button", { name: /Search/i });
    expect(searchButton).toBeInTheDocument();
    expect(searchButton.className).toContain("disabled");

    // column headers
    expect(screen.getByRole("columnheader", { name: "" })).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: "Job ID" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: "Start time" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: "End time" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: "Type" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: "Name" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: "Status" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: "Errors" }),
    ).toBeInTheDocument();

    // no data
    expect(screen.getByRole("cell", { name: "No Data" })).toBeInTheDocument();
  });

  test("Search page - search plugin name", async () => {
    // advanceTimers: true needed with user-event
    jest
      .useFakeTimers({ advanceTimers: true })
      .setSystemTime(new Date(2024, 10, 28));
    const user = userEvent.setup();
    axios.get.mockImplementation(() =>
      Promise.resolve({
        status: 200,
        data: {
          count: 1,
          total_pages: 1,
          results: [
            {
              job: { id: 2 },
              config: {
                name: "Classic_DNS",
                plugin_name: "analyzer",
              },
              status: "SUCCESS",
              start_time: "2024-11-26T09:56:59.555203Z",
              end_time: "2024-11-26T09:57:03.805453Z",
              errors: [],
              report: {
                observable: "google.com",
                resolutions: [
                  {
                    TTL: 268,
                    data: "216.58.205.46",
                    name: "google.com.",
                    type: 1,
                    Expires: "Wed, 26 Nov 2024 10:01:31 UTC",
                  },
                ],
              },
            },
          ],
        },
      }),
    );

    render(
      <BrowserRouter>
        <ReportsSearch />
      </BrowserRouter>,
    );

    const searchTitle = screen.getByRole("heading", { name: /Search/i });
    expect(searchTitle).toBeInTheDocument();
    const hitsText = screen.getByText("0 total");
    expect(hitsText).toBeInTheDocument();
    const searchDescription = screen.getByText(
      "Advanced search in plugin reports of the performed analysis.",
    );
    expect(searchDescription).toBeInTheDocument();

    // first row
    const typeField = screen.getByRole("combobox", { name: /Type:/i });
    expect(typeField).toBeInTheDocument();
    const nameField = screen.getByRole("textbox", { name: /Name:/i });
    expect(nameField).toBeInTheDocument();
    const statusField = screen.getByRole("combobox", { name: /Status:/i });
    expect(statusField).toBeInTheDocument();
    // second row
    const startTimeField = screen.getByText("Start time:");
    expect(startTimeField).toBeInTheDocument();
    const fromStartTimeInput = screen.getAllByText("from")[0];
    expect(fromStartTimeInput).toBeInTheDocument();
    const toStartTimeInput = screen.getAllByText("to")[0];
    expect(toStartTimeInput).toBeInTheDocument();
    const endTimeField = screen.getByText("End time:");
    expect(endTimeField).toBeInTheDocument();
    const fromEndTimeInput = screen.getAllByText("from")[1];
    expect(fromEndTimeInput).toBeInTheDocument();
    const toEndTimeInput = screen.getAllByText("to")[1];
    expect(toEndTimeInput).toBeInTheDocument();
    const errorsField = screen.getByRole("combobox", { name: /Errors:/i });
    expect(errorsField).toBeInTheDocument();
    // third row
    const fullTextField = screen.getByRole("textbox", {
      name: /Text search:/i,
    });
    expect(fullTextField).toBeInTheDocument();
    const searchButton = screen.getByRole("button", { name: /Search/i });
    expect(searchButton).toBeInTheDocument();
    expect(searchButton.className).toContain("disabled");

    // column headers
    expect(screen.getByRole("columnheader", { name: "" })).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: "Job ID" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: "Start time" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: "End time" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: "Type" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: "Name" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: "Status" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: "Errors" }),
    ).toBeInTheDocument();

    // no data
    expect(screen.getByRole("cell", { name: "No Data" })).toBeInTheDocument();

    // select plugin name
    await user.type(nameField, "Classic_DNS");

    expect(searchButton.className).not.toContain("disabled");
    await user.click(searchButton);

    const isoFormatString = "yyyy-MM-dd'T'HH:mm";
    const fromDate = new Date();
    fromDate.setDate(fromDate.getDate() - 30);
    const fromDateStr = format(fromDate, isoFormatString);

    await waitFor(() => {
      expect(axios.get).toHaveBeenCalledWith(`${PLUGIN_REPORT_QUERIES}`, {
        params: {
          name: "Classic_DNS",
          end_end_time: new Date(format(new Date(), isoFormatString)),
          end_start_time: new Date(format(new Date(), isoFormatString)),
          start_end_time: new Date(fromDateStr),
          start_start_time: new Date(fromDateStr),
          page: 1,
          page_size: 10,
        },
      });
      expect(screen.getByText("1 total")).toBeInTheDocument();
      expect(screen.getByText("#2")).toBeInTheDocument();
      const startTimeCell = screen.getAllByRole("cell")[2];
      expect(startTimeCell).toBeInTheDocument();
      const endTimeCell = screen.getAllByRole("cell")[3];
      expect(endTimeCell).toBeInTheDocument();
      expect(screen.getByText("analyzer")).toBeInTheDocument();
      expect(screen.getByText("Classic_DNS")).toBeInTheDocument();
      expect(screen.getAllByText("SUCCESS")[1]).toBeInTheDocument();
      expect(screen.getByText("0 errors")).toBeInTheDocument();
    });
  });
});
