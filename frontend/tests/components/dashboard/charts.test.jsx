import React from "react";
import useAxios from "axios-hooks";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import {
  JobFileMimetypeBarChart,
  JobObsClassificationBarChart,
  JobStatusBarChart,
  JobTopPlaybookBarChart,
  JobTopTLPBarChart,
  JobTopUserBarChart,
  JobTypeBarChart,
} from "../../../src/components/dashboard/charts";

jest.mock("axios-hooks");
jest.mock("recharts", () => {
  const OriginalModule = jest.requireActual("recharts");
  return {
    ...OriginalModule,
    // eslint-disable-next-line react/prop-types
    ResponsiveContainer: ({ children }) => (
      <OriginalModule.ResponsiveContainer width={800} height={800}>
        {children}
      </OriginalModule.ResponsiveContainer>
    ),
  };
});

describe("test dashboard's charts", () => {
  global.ResizeObserver = jest.fn().mockImplementation(() => ({
    observe: jest.fn(),
    unobserve: jest.fn(),
    disconnect: jest.fn(),
  }));

  beforeEach(() => {
    jest.clearAllMocks();
  });

  test("test JobStatusBarChart", async () => {
    useAxios.mockReturnValue([
      {
        data: [
          {
            date: "2024-11-28T22:00:00Z",
            pending: 0,
            reported_without_fails: 8,
            reported_with_fails: 0,
            failed: 0,
          },
          {
            date: "2024-11-29T22:00:00Z",
            pending: 0,
            reported_without_fails: 0,
            reported_with_fails: 1,
            failed: 1,
          },
          {
            date: "2024-11-29T23:00:00Z",
            pending: 0,
            reported_without_fails: 1,
            reported_with_fails: 2,
            failed: 0,
          },
        ],
        loading: false,
        error: null,
      },
    ]);

    render(<JobStatusBarChart orgName="testOrg" />);

    // needed to support different timezones (ex: ci and local could be different)
    expect(
      screen.getByText(
        `${new Date("2024-11-28T22:00:00Z").getDate()}/${new Date("2024-11-28T22:00:00Z").getMonth() + 1}, ${new Date("2024-11-28T22:00:00Z").getHours()}:00`,
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        `${new Date("2024-11-29T22:00:00Z").getDate()}/${new Date("2024-11-29T22:00:00Z").getMonth() + 1}, ${new Date("2024-11-29T22:00:00Z").getHours()}:00`,
      ),
    ).toBeInTheDocument();
    let hours = new Date("2024-11-29T23:00:00Z").getHours();
    if (hours === 0) hours = "00";
    expect(
      screen.getByText(
        `${new Date("2024-11-29T23:00:00Z").getDate()}/${new Date("2024-11-29T23:00:00Z").getMonth() + 1}, ${hours}:00`,
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("pending")).toBeInTheDocument();
    expect(screen.getByText("reported_without_fails")).toBeInTheDocument();
    expect(screen.getByText("reported_with_fails")).toBeInTheDocument();
    expect(screen.getByText("failed")).toBeInTheDocument();
  });

  test("test JobStatusBarChart no data", async () => {
    useAxios.mockReturnValue([
      {
        data: [],
        loading: false,
        error: null,
      },
    ]);

    render(<JobStatusBarChart orgName="testOrg" />);
    expect(
      screen.getByText("No data in the selected range."),
    ).toBeInTheDocument();
  });

  test("test JobTypeBarChart", async () => {
    useAxios.mockReturnValue([
      {
        data: [
          {
            date: "2024-11-28T22:00:00Z",
            file: 0,
            observable: 8,
          },
          {
            date: "2024-11-29T22:00:00Z",
            file: 2,
            observable: 0,
          },
          {
            date: "2024-11-29T23:00:00Z",
            file: 0,
            observable: 3,
          },
        ],
        loading: false,
        error: null,
      },
    ]);

    render(<JobTypeBarChart orgName="testOrg" />);

    // needed to support different timezones (ex: ci and local could be different)
    expect(
      screen.getByText(
        `${new Date("2024-11-28T22:00:00Z").getDate()}/${new Date("2024-11-28T22:00:00Z").getMonth() + 1}, ${new Date("2024-11-28T22:00:00Z").getHours()}:00`,
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        `${new Date("2024-11-29T22:00:00Z").getDate()}/${new Date("2024-11-29T22:00:00Z").getMonth() + 1}, ${new Date("2024-11-29T22:00:00Z").getHours()}:00`,
      ),
    ).toBeInTheDocument();
    let hours = new Date("2024-11-29T23:00:00Z").getHours();
    if (hours === 0) hours = "00";
    expect(
      screen.getByText(
        `${new Date("2024-11-29T23:00:00Z").getDate()}/${new Date("2024-11-29T23:00:00Z").getMonth() + 1}, ${hours}:00`,
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("file")).toBeInTheDocument();
    expect(screen.getByText("observable")).toBeInTheDocument();
  });

  test("test JobTypeBarChart no data", async () => {
    useAxios.mockReturnValue([
      {
        data: [],
        loading: false,
        error: null,
      },
    ]);

    render(<JobTypeBarChart orgName="testOrg" />);
    expect(
      screen.getByText("No data in the selected range."),
    ).toBeInTheDocument();
  });

  test("test JobObsClassificationBarChart", async () => {
    useAxios.mockReturnValue([
      {
        data: [
          {
            date: "2024-11-28T22:00:00Z",
            ip: 0,
            url: 0,
            domain: 1,
            hash: 0,
            generic: 0,
          },
          {
            date: "2024-11-29T22:00:00Z",
            ip: 0,
            url: 0,
            domain: 0,
            hash: 0,
            generic: 0,
          },
          {
            date: "2024-11-29T23:00:00Z",
            ip: 0,
            url: 0,
            domain: 3,
            hash: 0,
            generic: 0,
          },
        ],
        loading: false,
        error: null,
      },
    ]);

    render(<JobObsClassificationBarChart orgName="testOrg" />);

    // needed to support different timezones (ex: ci and local could be different)
    expect(
      screen.getByText(
        `${new Date("2024-11-28T22:00:00Z").getDate()}/${new Date("2024-11-28T22:00:00Z").getMonth() + 1}, ${new Date("2024-11-28T22:00:00Z").getHours()}:00`,
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        `${new Date("2024-11-29T22:00:00Z").getDate()}/${new Date("2024-11-29T22:00:00Z").getMonth() + 1}, ${new Date("2024-11-29T22:00:00Z").getHours()}:00`,
      ),
    ).toBeInTheDocument();
    let hours = new Date("2024-11-29T23:00:00Z").getHours();
    if (hours === 0) hours = "00";
    expect(
      screen.getByText(
        `${new Date("2024-11-29T23:00:00Z").getDate()}/${new Date("2024-11-29T23:00:00Z").getMonth() + 1}, ${hours}:00`,
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("ip")).toBeInTheDocument();
    expect(screen.getByText("url")).toBeInTheDocument();
    expect(screen.getByText("domain")).toBeInTheDocument();
    expect(screen.getByText("hash")).toBeInTheDocument();
    expect(screen.getByText("generic")).toBeInTheDocument();
  });

  test("test JobObsClassificationBarChart no data", async () => {
    useAxios.mockReturnValue([
      {
        data: [],
        loading: false,
        error: null,
      },
    ]);

    render(<JobObsClassificationBarChart orgName="testOrg" />);
    expect(
      screen.getByText("No data in the selected range."),
    ).toBeInTheDocument();
  });

  test("test JobFileMimetypeBarChart", async () => {
    useAxios.mockReturnValue([
      {
        data: {
          values: ["application/json", "text/plain"],
          aggregation: [
            {
              date: "2024-11-28T22:00:00Z",
              "application/json": 0,
              "text/plain": 0,
            },
            {
              date: "2024-11-29T22:00:00Z",
              "application/json": 1,
              "text/plain": 1,
            },
            {
              date: "2024-11-29T23:00:00Z",
              "application/json": 0,
              "text/plain": 0,
            },
          ],
        },
        loading: false,
        error: null,
      },
    ]);

    render(<JobFileMimetypeBarChart orgName="testOrg" />);

    // needed to support different timezones (ex: ci and local could be different)
    expect(
      screen.getByText(
        `${new Date("2024-11-28T22:00:00Z").getDate()}/${new Date("2024-11-28T22:00:00Z").getMonth() + 1}, ${new Date("2024-11-28T22:00:00Z").getHours()}:00`,
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        `${new Date("2024-11-29T22:00:00Z").getDate()}/${new Date("2024-11-29T22:00:00Z").getMonth() + 1}, ${new Date("2024-11-29T22:00:00Z").getHours()}:00`,
      ),
    ).toBeInTheDocument();
    let hours = new Date("2024-11-29T23:00:00Z").getHours();
    if (hours === 0) hours = "00";
    expect(
      screen.getByText(
        `${new Date("2024-11-29T23:00:00Z").getDate()}/${new Date("2024-11-29T23:00:00Z").getMonth() + 1}, ${hours}:00`,
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("application/json")).toBeInTheDocument();
    expect(screen.getByText("text/plain")).toBeInTheDocument();
  });

  test("test JobFileMimetypeBarChart no data", async () => {
    useAxios.mockReturnValue([
      {
        data: [],
        loading: false,
        error: null,
      },
    ]);

    render(<JobFileMimetypeBarChart orgName="testOrg" />);
    expect(
      screen.getByText("No data in the selected range."),
    ).toBeInTheDocument();
  });

  test("test JobTopPlaybookBarChart", async () => {
    useAxios.mockReturnValue([
      {
        data: {
          values: ["Dns", "FREE_TO_USE_ANALYZERS", "Passive_DNS"],
          aggregation: [
            {
              date: "2024-11-28T22:00:00Z",
              Dns: 5,
              FREE_TO_USE_ANALYZERS: 1,
              Passive_DNS: 3,
            },
            {
              date: "2024-11-29T22:00:00Z",
              Dns: 1,
              FREE_TO_USE_ANALYZERS: 0,
              Passive_DNS: 0,
            },
            {
              date: "2024-11-29T23:00:00Z",
              Dns: 1,
              FREE_TO_USE_ANALYZERS: 0,
              Passive_DNS: 0,
            },
          ],
        },
        loading: false,
        error: null,
      },
    ]);

    render(<JobTopPlaybookBarChart orgName="testOrg" />);

    // needed to support different timezones (ex: ci and local could be different)
    expect(
      screen.getByText(
        `${new Date("2024-11-28T22:00:00Z").getDate()}/${new Date("2024-11-28T22:00:00Z").getMonth() + 1}, ${new Date("2024-11-28T22:00:00Z").getHours()}:00`,
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        `${new Date("2024-11-29T22:00:00Z").getDate()}/${new Date("2024-11-29T22:00:00Z").getMonth() + 1}, ${new Date("2024-11-29T22:00:00Z").getHours()}:00`,
      ),
    ).toBeInTheDocument();
    let hours = new Date("2024-11-29T23:00:00Z").getHours();
    if (hours === 0) hours = "00";
    expect(
      screen.getByText(
        `${new Date("2024-11-29T23:00:00Z").getDate()}/${new Date("2024-11-29T23:00:00Z").getMonth() + 1}, ${hours}:00`,
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("Dns")).toBeInTheDocument();
    expect(screen.getByText("FREE_TO_USE_ANALYZERS")).toBeInTheDocument();
    expect(screen.getByText("Passive_DNS")).toBeInTheDocument();
  });

  test("test JobTopPlaybookBarChart no data", async () => {
    useAxios.mockReturnValue([
      {
        data: [],
        loading: false,
        error: null,
      },
    ]);

    render(<JobTopPlaybookBarChart orgName="testOrg" />);
    expect(
      screen.getByText("No data in the selected range."),
    ).toBeInTheDocument();
  });

  test("test JobTopUserBarChart", async () => {
    useAxios.mockReturnValue([
      {
        data: {
          values: ["user_a", "user_b", "user_c"],
          aggregation: [
            {
              date: "2024-11-28T22:00:00Z",
              user_a: 5,
              user_b: 1,
              user_c: 3,
            },
            {
              date: "2024-11-29T22:00:00Z",
              user_a: 1,
              user_b: 0,
              user_c: 0,
            },
            {
              date: "2024-11-29T23:00:00Z",
              user_a: 1,
              user_b: 0,
              user_c: 0,
            },
          ],
        },
        loading: false,
        error: null,
      },
    ]);

    render(<JobTopUserBarChart orgName="testOrg" />);

    // needed to support different timezones (ex: ci and local could be different)
    expect(
      screen.getByText(
        `${new Date("2024-11-28T22:00:00Z").getDate()}/${new Date("2024-11-28T22:00:00Z").getMonth() + 1}, ${new Date("2024-11-28T22:00:00Z").getHours()}:00`,
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        `${new Date("2024-11-29T22:00:00Z").getDate()}/${new Date("2024-11-29T22:00:00Z").getMonth() + 1}, ${new Date("2024-11-29T22:00:00Z").getHours()}:00`,
      ),
    ).toBeInTheDocument();
    let hours = new Date("2024-11-29T23:00:00Z").getHours();
    if (hours === 0) hours = "00";
    expect(
      screen.getByText(
        `${new Date("2024-11-29T23:00:00Z").getDate()}/${new Date("2024-11-29T23:00:00Z").getMonth() + 1}, ${hours}:00`,
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("user_a")).toBeInTheDocument();
    expect(screen.getByText("user_b")).toBeInTheDocument();
    expect(screen.getByText("user_c")).toBeInTheDocument();
  });

  test("test JobTopUserBarChart no data", async () => {
    useAxios.mockReturnValue([
      {
        data: [],
        loading: false,
        error: null,
      },
    ]);

    render(<JobTopUserBarChart orgName="testOrg" />);
    expect(
      screen.getByText("No data in the selected range."),
    ).toBeInTheDocument();
  });

  test("test JobTopTLPBarChart", async () => {
    useAxios.mockReturnValue([
      {
        data: {
          values: ["AMBER", "CLEAR", "RED"],
          aggregation: [
            {
              date: "2024-11-28T22:00:00Z",
              AMBER: 5,
              CLEAR: 1,
              RED: 3,
            },
            {
              date: "2024-11-29T22:00:00Z",
              AMBER: 1,
              CLEAR: 0,
              RED: 0,
            },
            {
              date: "2024-11-29T23:00:00Z",
              AMBER: 1,
              CLEAR: 0,
              RED: 0,
            },
          ],
        },
        loading: false,
        error: null,
      },
    ]);

    render(<JobTopTLPBarChart orgName="testOrg" />);

    // needed to support different timezones (ex: ci and local could be different)
    expect(
      screen.getByText(
        `${new Date("2024-11-28T22:00:00Z").getDate()}/${new Date("2024-11-28T22:00:00Z").getMonth() + 1}, ${new Date("2024-11-28T22:00:00Z").getHours()}:00`,
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        `${new Date("2024-11-29T22:00:00Z").getDate()}/${new Date("2024-11-29T22:00:00Z").getMonth() + 1}, ${new Date("2024-11-29T22:00:00Z").getHours()}:00`,
      ),
    ).toBeInTheDocument();
    let hours = new Date("2024-11-29T23:00:00Z").getHours();
    if (hours === 0) hours = "00";
    expect(
      screen.getByText(
        `${new Date("2024-11-29T23:00:00Z").getDate()}/${new Date("2024-11-29T23:00:00Z").getMonth() + 1}, ${hours}:00`,
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("AMBER")).toBeInTheDocument();
    expect(screen.getByText("CLEAR")).toBeInTheDocument();
    expect(screen.getByText("RED")).toBeInTheDocument();
  });

  test("test JobTopTLPBarChart no data", async () => {
    useAxios.mockReturnValue([
      {
        data: [],
        loading: false,
        error: null,
      },
    ]);

    render(<JobTopTLPBarChart orgName="testOrg" />);
    expect(
      screen.getByText("No data in the selected range."),
    ).toBeInTheDocument();
  });
});
