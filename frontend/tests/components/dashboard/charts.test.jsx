import React from "react";
import useAxios from "axios-hooks";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { JobFileMimetypeBarChart, JobObsClassificationBarChart, JobStatusBarChart, JobTypeBarChart } from "../../../src/components/dashboard/charts";


jest.mock("axios-hooks");
jest.mock('recharts', () => {
    const OriginalModule = jest.requireActual('recharts')
    return {
        ...OriginalModule,
        ResponsiveContainer: ({ children }) => (
            <OriginalModule.ResponsiveContainer width={800} height={800}>
                {children}
            </OriginalModule.ResponsiveContainer>
        ),
    }
})


describe("test dashboard's charts", () => {
    global.ResizeObserver = jest.fn().mockImplementation(() => ({
        observe: jest.fn(),
        unobserve: jest.fn(),
        disconnect: jest.fn(),
    }))
    
    beforeEach(() => {
        jest.clearAllMocks();
    });

    test("test JobStatusBarChart", async () => {

        useAxios.mockReturnValue([
            {
                data: [
                    {
                        "date": "2024-11-28T14:00:00Z",
                        "pending": 0,
                        "reported_without_fails": 8,
                        "reported_with_fails": 0,
                        "failed": 0
                    },
                    {
                        "date": "2024-11-29T10:00:00Z",
                        "pending": 0,
                        "reported_without_fails": 0,
                        "reported_with_fails": 1,
                        "failed": 1
                    },
                    {
                        "date": "2024-11-29T09:00:00Z",
                        "pending": 0,
                        "reported_without_fails": 1,
                        "reported_with_fails": 2,
                        "failed": 0
                    }
                ],
                loading: false,
                error: null
            },
        ]);

        render(<JobStatusBarChart orgName="testOrg" />);
        screen.debug(undefined, Infinity)

        // needed to support different timezones (ex: ci and local could be different)
        expect(screen.getByText(`28/11, ${  new Date('2024-11-28T14:00:00Z').getHours()  }:00`)).toBeInTheDocument();
        expect(screen.getByText(`29/11, ${  new Date('2024-11-29T10:00:00Z').getHours()  }:00`)).toBeInTheDocument();
        expect(screen.getByText(`29/11, ${  new Date('2024-11-29T09:00:00Z').getHours()  }:00`)).toBeInTheDocument();
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
                error: null
            },
        ]);

        render(<JobStatusBarChart orgName="testOrg" />);
        expect(screen.getByText("No data in the selected range.")).toBeInTheDocument();
    });

    test("test JobTypeBarChart", async () => {

        useAxios.mockReturnValue([
            {
                data: [
                    {
                        "date": "2024-11-28T14:00:00Z",
                        "file": 0,
                        "observable": 8
                    },
                    {
                        "date": "2024-11-29T10:00:00Z",
                        "file": 2,
                        "observable": 0
                    },
                    {
                        "date": "2024-11-29T09:00:00Z",
                        "file": 0,
                        "observable": 3
                    }
                ],
                loading: false,
                error: null
            },
        ]);

        render(<JobTypeBarChart orgName="testOrg" />);
        screen.debug(undefined, Infinity)

        // needed to support different timezones (ex: ci and local could be different)
        expect(screen.getByText(`28/11, ${  new Date('2024-11-28T14:00:00Z').getHours()  }:00`)).toBeInTheDocument();
        expect(screen.getByText(`29/11, ${  new Date('2024-11-29T10:00:00Z').getHours()  }:00`)).toBeInTheDocument();
        expect(screen.getByText(`29/11, ${  new Date('2024-11-29T09:00:00Z').getHours()  }:00`)).toBeInTheDocument();
        expect(screen.getByText("file")).toBeInTheDocument();
        expect(screen.getByText("observable")).toBeInTheDocument();
    });

    test("test JobTypeBarChart no data", async () => {
        useAxios.mockReturnValue([
            {
                data: [],
                loading: false,
                error: null
            },
        ]);

        render(<JobTypeBarChart orgName="testOrg" />);
        expect(screen.getByText("No data in the selected range.")).toBeInTheDocument();
    });

    test("test JobObsClassificationBarChart", async () => {

        useAxios.mockReturnValue([
            {
                data: [
                    {
                            "date": "2024-11-28T14:00:00Z",
                            "ip": 0,
                            "url": 0,
                            "domain": 1,
                            "hash": 0,
                            "generic": 0
                        },
                        {
                            "date": "2024-11-29T10:00:00Z",
                            "ip": 0,
                            "url": 0,
                            "domain": 0,
                            "hash": 0,
                            "generic": 0
                        },
                        {
                            "date": "2024-11-29T09:00:00Z",
                            "ip": 0,
                            "url": 0,
                            "domain": 3,
                            "hash": 0,
                            "generic": 0
                        }
                ],
                loading: false,
                error: null
            },
        ]);

        render(<JobObsClassificationBarChart orgName="testOrg" />);
        screen.debug(undefined, Infinity)

        // needed to support different timezones (ex: ci and local could be different)
        expect(screen.getByText(`28/11, ${  new Date('2024-11-28T14:00:00Z').getHours()  }:00`)).toBeInTheDocument();
        expect(screen.getByText(`29/11, ${  new Date('2024-11-29T10:00:00Z').getHours()  }:00`)).toBeInTheDocument();
        expect(screen.getByText(`29/11, ${  new Date('2024-11-29T09:00:00Z').getHours()  }:00`)).toBeInTheDocument();
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
                error: null
            },
        ]);

        render(<JobObsClassificationBarChart orgName="testOrg" />);
        expect(screen.getByText("No data in the selected range.")).toBeInTheDocument();
    });

    test("test JobFileMimetypeBarChart", async () => {

        useAxios.mockReturnValue([
            {
                data: {
                    "values": [
                        "application/json",
                        "text/plain"
                    ],
                    "aggregation": [
                        {
                            "date": "2024-11-28T14:00:00Z",
                            "application/json": 0,
                            "text/plain": 0
                        },
                        {
                            "date": "2024-11-29T10:00:00Z",
                            "application/json": 1,
                            "text/plain": 1
                        },
                        {
                            "date": "2024-11-29T09:00:00Z",
                            "application/json": 0,
                            "text/plain": 0
                        }
                    ]
                },
                loading: false,
                error: null
            },
        ]);

        render(<JobFileMimetypeBarChart orgName="testOrg" />);
        screen.debug(undefined, Infinity)

        // needed to support different timezones (ex: ci and local could be different)
        expect(screen.getByText(`28/11, ${  new Date('2024-11-28T14:00:00Z').getHours()  }:00`)).toBeInTheDocument();
        expect(screen.getByText(`29/11, ${  new Date('2024-11-29T10:00:00Z').getHours()  }:00`)).toBeInTheDocument();
        expect(screen.getByText(`29/11, ${  new Date('2024-11-29T09:00:00Z').getHours()  }:00`)).toBeInTheDocument();
        expect(screen.getByText("application/json")).toBeInTheDocument();
        expect(screen.getByText("text/plain")).toBeInTheDocument();
    });

    test("test JobFileMimetypeBarChart no data", async () => {
        useAxios.mockReturnValue([
            {
                data: [],
                loading: false,
                error: null
            },
        ]);

        render(<JobFileMimetypeBarChart orgName="testOrg" />);
        expect(screen.getByText("No data in the selected range.")).toBeInTheDocument();
    });

});
