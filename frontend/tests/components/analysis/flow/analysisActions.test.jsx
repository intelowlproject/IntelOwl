import React from "react";
import axios from "axios";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import {
  AddExistingJobPopover,
  RemoveJob,
} from "../../../../src/components/analysis/flow/analysisActions";
import {
  ANALYSIS_BASE_URI,
  JOB_BASE_URI,
} from "../../../../src/constants/apiURLs";
import Toast from "../../../../src/layouts/Toast";

jest.mock("axios");

describe("test AddExistingJobPopover", () => {
  test("job is not part of any analysis", async () => {
    axios.get.mockImplementation(() =>
      Promise.resolve({ status: 200, data: { id: 1, analysis: null } }),
    );
    axios.post.mockImplementation(() => Promise.resolve({ status: 200 }));

    const { container } = render(
      <BrowserRouter>
        <AddExistingJobPopover
          data={{
            id: 1,
            refetchTree: () => jest.fn(),
            refetchAnalysis: () => jest.fn(),
          }}
        />
        <Toast />
      </BrowserRouter>,
    );
    const user = userEvent.setup();

    const addJobButton = container.querySelector("#addExistingJobBtn");
    expect(addJobButton).toBeInTheDocument();

    await user.click(addJobButton);

    const inputArea = screen.getByRole("textbox");
    expect(inputArea).toBeInTheDocument();
    const addButton = screen.getByRole("button", { name: "Add" });
    expect(addButton).toBeInTheDocument();

    await user.type(inputArea, "1");
    await user.click(addButton);

    await waitFor(() => {
      expect(axios.get.mock.calls.length).toBe(1);
      expect(axios.post.mock.calls.length).toBe(1);
      expect(axios.get).toHaveBeenCalledWith(`${JOB_BASE_URI}/1`);
      expect(axios.post).toHaveBeenCalledWith(
        `${ANALYSIS_BASE_URI}/1/add_job`,
        { job: "1" },
      );
      const toastInfo = screen.getByText("Job #1 added to the Analysis #1");
      expect(toastInfo).toBeInTheDocument();
    });
  });

  test("Job is already part of this analysis", async () => {
    axios.get.mockImplementation(() =>
      Promise.resolve({ status: 200, data: { id: 2, analysis: 1 } }),
    );

    const { container } = render(
      <BrowserRouter>
        <AddExistingJobPopover
          data={{
            id: 1,
            refetchTree: () => jest.fn(),
            refetchAnalysis: () => jest.fn(),
          }}
        />
        <Toast />
      </BrowserRouter>,
    );
    const user = userEvent.setup();

    const addJobButton = container.querySelector("#addExistingJobBtn");
    expect(addJobButton).toBeInTheDocument();

    await user.click(addJobButton);

    const inputArea = screen.getByRole("textbox");
    expect(inputArea).toBeInTheDocument();
    const addButton = screen.getByRole("button", { name: "Add" });
    expect(addButton).toBeInTheDocument();

    await user.type(inputArea, "2");
    await user.click(addButton);

    await waitFor(() => {
      expect(axios.get.mock.calls.length).toBe(1);
      expect(axios.get).toHaveBeenCalledWith(`${JOB_BASE_URI}/2`);
      const toastWarning = screen.getByText(
        "Job is already part of this analysis",
      );
      expect(toastWarning).toBeInTheDocument();
    });
  });

  test("job is already part of different analysis", async () => {
    axios.get.mockImplementation(() =>
      Promise.resolve({ status: 200, data: { id: 3, analysis: 4 } }),
    );
    axios.post.mockImplementation(() => Promise.resolve({ status: 200 }));
    axios.post.mockImplementation(() => Promise.resolve({ status: 200 }));

    const { container } = render(
      <BrowserRouter>
        <AddExistingJobPopover
          data={{
            id: 1,
            refetchTree: () => jest.fn(),
            refetchAnalysis: () => jest.fn(),
          }}
        />
        <Toast />
      </BrowserRouter>,
    );
    const user = userEvent.setup();

    const addJobButton = container.querySelector("#addExistingJobBtn");
    expect(addJobButton).toBeInTheDocument();

    await user.click(addJobButton);

    const inputArea = screen.getByRole("textbox");
    expect(inputArea).toBeInTheDocument();
    const addButton = screen.getByRole("button", { name: "Add" });
    expect(addButton).toBeInTheDocument();

    await user.type(inputArea, "3");
    await user.click(addButton);

    // confirm dialog
    const confirmButton = screen.getByRole("button", {
      name: "Ok",
    });
    await user.click(confirmButton);

    await waitFor(() => {
      expect(axios.get.mock.calls.length).toBe(1);
      expect(axios.post.mock.calls.length).toBe(2);
      expect(axios.get).toHaveBeenCalledWith(`${JOB_BASE_URI}/3`);
      expect(axios.post).toHaveBeenCalledWith(
        `${ANALYSIS_BASE_URI}/4/remove_job`,
        { job: "3" },
      );
      const toastWarning = screen.getByText(
        "Job #3 removed from the Analysis #4",
      );
      expect(toastWarning).toBeInTheDocument();
      expect(axios.post).toHaveBeenCalledWith(
        `${ANALYSIS_BASE_URI}/1/add_job`,
        { job: "3" },
      );
      const toastInfo = screen.getByText("Job #3 added to the Analysis #1");
      expect(toastInfo).toBeInTheDocument();
    });
  });
});

describe("test RemoveJob", () => {
  test("remove job button", async () => {
    axios.post.mockImplementation(() => Promise.resolve({ status: 200 }));

    render(
      <BrowserRouter>
        <RemoveJob
          data={{
            id: 1,
            analysis: 3,
            refetchTree: () => jest.fn(),
            refetchAnalysis: () => jest.fn(),
          }}
        />
        <Toast />
      </BrowserRouter>,
    );
    const user = userEvent.setup();

    const removeJobButton = screen.getByRole("button", { name: "Remove Job" });
    expect(removeJobButton).toBeInTheDocument();

    await user.click(removeJobButton);

    await waitFor(() => {
      expect(axios.post.mock.calls.length).toBe(1);
      expect(axios.post).toHaveBeenCalledWith(
        `${ANALYSIS_BASE_URI}/3/remove_job`,
        { job: 1 },
      );
      const toastInfo = screen.getByText("Job #1 removed from the Analysis #3");
      expect(toastInfo).toBeInTheDocument();
    });
  });
});
