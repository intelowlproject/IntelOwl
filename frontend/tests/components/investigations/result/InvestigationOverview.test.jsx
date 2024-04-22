import React from "react";
import axios from "axios";
import useAxios from "axios-hooks";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import { InvestigationOverview } from "../../../../src/components/investigations/result/InvestigationOverview";
import { INVESTIGATION_BASE_URI } from "../../../../src/constants/apiURLs";

jest.mock("axios");
jest.mock("axios-hooks");
// mock flow component
jest.mock(
  "../../../../src/components/investigations/flow/InvestigationFlow",
  () => jest.fn(),
);

describe("test InvestigationOverview", () => {
  beforeAll(() => {
    // mock useAxios call
    const investigationTree = {
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
      { investigationTree, loading, error },
      refetchTree,
    ]);
  });

  test("InvestigationOverview components", () => {
    const { container } = render(
      <BrowserRouter>
        <InvestigationOverview
          isRunningInvestigation={false}
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
          refetchInvestigation={() => jest.fn()}
        />
      </BrowserRouter>,
    );
    // Page title
    expect(
      screen.getByRole("heading", { name: "Investigation #1" }),
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
    expect(
      container.querySelector("#edit-investigation-name"),
    ).toBeInTheDocument();
    // description
    expect(screen.getByText("Description")).toBeInTheDocument();
    expect(screen.getByText("test description")).toBeInTheDocument();
    // edit description icon
    expect(
      container.querySelector("#edit-investigation-description"),
    ).toBeInTheDocument();
    // markdown icon
    expect(
      container.querySelector("#investigation-markdown-doc"),
    ).toBeInTheDocument();
  });

  test("Edit name", async () => {
    axios.patch.mockImplementation(() => Promise.resolve({ data: {} }));
    const { container } = render(
      <BrowserRouter>
        <InvestigationOverview
          isRunningInvestigation={false}
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
          refetchInvestigation={() => jest.fn()}
        />
      </BrowserRouter>,
    );
    const user = userEvent.setup();
    // Page title
    expect(
      screen.getByRole("heading", { name: "Investigation #1" }),
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
    const editNameButton = container.querySelector("#edit-investigation-name");
    expect(editNameButton).toBeInTheDocument();
    // description
    expect(screen.getByText("Description")).toBeInTheDocument();
    expect(screen.getByText("test description")).toBeInTheDocument();
    // edit description icon
    expect(
      container.querySelector("#edit-investigation-description"),
    ).toBeInTheDocument();
    // markdown icon
    expect(
      container.querySelector("#investigation-markdown-doc"),
    ).toBeInTheDocument();

    await user.click(editNameButton);
    const editNameInput = container.querySelector(
      "#edit-investigation-name-input",
    );
    expect(editNameInput).toBeInTheDocument();
    const viewName = container.querySelector("#save-investigation-name");
    expect(viewName).toBeInTheDocument();

    await user.type(editNameInput, " - edited name");
    await user.click(viewName);
    await waitFor(() => {
      expect(axios.patch.mock.calls.length).toBe(1);
      expect(axios.patch).toHaveBeenCalledWith(`${INVESTIGATION_BASE_URI}/1`, {
        name: "My test - edited name",
      });
    });
  });

  test("Edit description", async () => {
    axios.patch.mockImplementation(() => Promise.resolve({ data: {} }));
    const { container } = render(
      <BrowserRouter>
        <InvestigationOverview
          isRunningInvestigation={false}
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
          refetchInvestigation={() => jest.fn()}
        />
      </BrowserRouter>,
    );
    const user = userEvent.setup();
    // Page title
    expect(
      screen.getByRole("heading", { name: "Investigation #1" }),
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
    const editNameButton = container.querySelector("#edit-investigation-name");
    expect(editNameButton).toBeInTheDocument();
    // description
    expect(screen.getByText("Description")).toBeInTheDocument();
    expect(screen.getByText("test description")).toBeInTheDocument();
    // edit description icon
    const editDescriptionButton = container.querySelector(
      "#edit-investigation-description",
    );
    expect(editDescriptionButton).toBeInTheDocument();
    // markdown icon
    expect(
      container.querySelector("#investigation-markdown-doc"),
    ).toBeInTheDocument();

    await user.click(editDescriptionButton);
    const editDescriptionInput = container.querySelector(
      "#edit-investigation-description-input",
    );
    expect(editDescriptionInput).toBeInTheDocument();
    const viewDescription = container.querySelector(
      "#save-investigation-description",
    );
    expect(viewDescription).toBeInTheDocument();

    await user.type(editDescriptionInput, " - edited description");
    await user.click(viewDescription);
    await waitFor(() => {
      expect(axios.patch.mock.calls.length).toBe(1);
      expect(axios.patch).toHaveBeenCalledWith(`${INVESTIGATION_BASE_URI}/1`, {
        description: "test description - edited description",
      });
    });
  });
});
