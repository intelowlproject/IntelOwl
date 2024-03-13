import React from "react";
import axios from "axios";
import useAxios from "axios-hooks";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import { AnalysisOverview } from "../../../../src/components/analysis/result/AnalysisOverview";
import { ANALYSIS_BASE_URI } from "../../../../src/constants/apiURLs";

jest.mock("axios");
jest.mock("axios-hooks");
// mock flow component
jest.mock("../../../../src/components/analysis/flow/AnalysisFlow", () =>
  jest.fn(),
);

describe("test AnalysisOverview", () => {
  beforeAll(() => {
    // mock useAxios call
    const analysisTree = {
      name: "My test",
      owner: 2,
      jobs: [
        {
          pk: 45,
          observable_name: "test10.com",
          file_name: "",
          is_sample: false,
          playbook: "Dns",
          status: "reported_without_fails",
          children: [],
        },
      ],
    };
    const loading = false;
    const error = {};
    const refetchTree = () => jest.fn();

    useAxios.mockImplementation(() => [
      { analysisTree, loading, error },
      refetchTree,
    ]);
  });

  test("AnalysisOverview components", () => {
    const { container } = render(
      <BrowserRouter>
        <AnalysisOverview
          isRunningAnalysis={false}
          analysis={{
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
          refetchAnalysis={() => jest.fn()}
        />
      </BrowserRouter>,
    );
    // Page title
    expect(
      screen.getByRole("heading", { name: "Analysis #1" }),
    ).toBeInTheDocument();
    // status
    expect(
      container.querySelector("#statusicon-concluded"),
    ).toBeInTheDocument();
    // name
    expect(
      screen.getByRole("heading", { name: "My test" }),
    ).toBeInTheDocument();
    // edit name icon
    expect(container.querySelector("#edit-analysis-name")).toBeInTheDocument();
    // description
    expect(screen.getByText("Description")).toBeInTheDocument();
    expect(screen.getByText("test description")).toBeInTheDocument();
    // edit description icon
    expect(
      container.querySelector("#edit-analysis-description"),
    ).toBeInTheDocument();
  });

  test("Edit name", async () => {
    axios.patch.mockImplementation(() => Promise.resolve({ data: {} }));
    const { container } = render(
      <BrowserRouter>
        <AnalysisOverview
          isRunningAnalysis={false}
          analysis={{
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
          refetchAnalysis={() => jest.fn()}
        />
      </BrowserRouter>,
    );
    const user = userEvent.setup();
    // Page title
    expect(
      screen.getByRole("heading", { name: "Analysis #1" }),
    ).toBeInTheDocument();
    // status
    expect(
      container.querySelector("#statusicon-concluded"),
    ).toBeInTheDocument();
    // name
    expect(
      screen.getByRole("heading", { name: "My test" }),
    ).toBeInTheDocument();
    // edit name icon
    const editNameButton = container.querySelector("#edit-analysis-name");
    expect(editNameButton).toBeInTheDocument();
    // description
    expect(screen.getByText("Description")).toBeInTheDocument();
    expect(screen.getByText("test description")).toBeInTheDocument();
    // edit description icon
    expect(
      container.querySelector("#edit-analysis-description"),
    ).toBeInTheDocument();

    await user.click(editNameButton);
    const editNameInput = container.querySelector("#edit_analysis-input");
    expect(editNameInput).toBeInTheDocument();
    const viewName = container.querySelector("#view-analysis-name");
    expect(viewName).toBeInTheDocument();

    await user.type(editNameInput, " - edited name");
    await user.click(viewName);
    await waitFor(() => {
      expect(axios.patch.mock.calls.length).toBe(1);
      expect(axios.patch).toHaveBeenCalledWith(`${ANALYSIS_BASE_URI}/1`, {
        name: "My test - edited name",
      });
    });
  });

  test("Edit description", async () => {
    axios.patch.mockImplementation(() => Promise.resolve({ data: {} }));
    const { container } = render(
      <BrowserRouter>
        <AnalysisOverview
          isRunningAnalysis={false}
          analysis={{
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
          refetchAnalysis={() => jest.fn()}
        />
      </BrowserRouter>,
    );
    const user = userEvent.setup();
    // Page title
    expect(
      screen.getByRole("heading", { name: "Analysis #1" }),
    ).toBeInTheDocument();
    // status
    expect(
      container.querySelector("#statusicon-concluded"),
    ).toBeInTheDocument();
    // name
    expect(
      screen.getByRole("heading", { name: "My test" }),
    ).toBeInTheDocument();
    // edit name icon
    const editNameButton = container.querySelector("#edit-analysis-name");
    expect(editNameButton).toBeInTheDocument();
    // description
    expect(screen.getByText("Description")).toBeInTheDocument();
    expect(screen.getByText("test description")).toBeInTheDocument();
    // edit description icon
    const editDescriptionButton = container.querySelector(
      "#edit-analysis-description",
    );
    expect(editDescriptionButton).toBeInTheDocument();

    await user.click(editDescriptionButton);
    const editDescriptionInput = container.querySelector(
      "#edit_analysis-input",
    );
    expect(editDescriptionInput).toBeInTheDocument();
    const viewDescription = container.querySelector(
      "#view-analysis-description",
    );
    expect(viewDescription).toBeInTheDocument();

    await user.type(editDescriptionInput, " - edited description");
    await user.click(viewDescription);
    await waitFor(() => {
      expect(axios.patch.mock.calls.length).toBe(1);
      expect(axios.patch).toHaveBeenCalledWith(`${ANALYSIS_BASE_URI}/1`, {
        description: "test description - edited description",
      });
    });
  });
});
