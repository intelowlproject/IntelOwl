import React from "react";
import "@testing-library/jest-dom";
import md5 from "md5";
import axios from "axios";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import RecentScans from "../../../../src/components/scan/utils/RecentScans";
import {
  JOB_RECENT_SCANS,
  JOB_RECENT_SCANS_USER,
} from "../../../../src/constants/apiURLs";

jest.mock("axios");

describe("Recent Scans test", () => {
  const recentScansUser = [
    {
      file_name: "",
      finished_analysis_time: "2023-08-21T15:43:13.896626Z",
      importance: 3,
      observable_name: "test.it",
      pk: 1,
      playbook: "dns",
      tlp: "AMBER",
      user: "test",
    },
  ];
  const recentScansObservable = [
    {
      file_name: "",
      finished_analysis_time: "2023-08-25T15:43:13.896626Z",
      importance: 5,
      observable_name: "1.2.3.4",
      pk: 2,
      playbook: "ip",
      tlp: "CLEAR",
      user: "t.test",
    },
  ];

  test("Recent scans - default", async () => {
    axios.post.mockImplementation((url) => {
      switch (url) {
        case JOB_RECENT_SCANS_USER:
          return Promise.resolve({ data: [] });
        case JOB_RECENT_SCANS:
          return Promise.resolve({ data: [] });
        default:
          return Promise.reject(new Error("Error"));
      }
    });

    const { container } = render(
      <BrowserRouter>
        <RecentScans classification="generic" param="" />
      </BrowserRouter>,
    );

    await waitFor(() => {
      const recentScansTitle = screen.getByText("Recent Scans");
      expect(recentScansTitle).toBeInTheDocument();
      const recentScansInfoIcon = container.querySelector(
        "#recentscans-info-icon",
      );
      expect(recentScansInfoIcon).toBeInTheDocument();
      const recentScansTotal = screen.getByText("0 total");
      expect(recentScansTotal).toBeInTheDocument();
      const elementText = screen.getByText("No recent scans available");
      expect(elementText).toBeInTheDocument();
    });

    // axios call
    expect(axios.post.mock.calls[0]).toEqual([
      JOB_RECENT_SCANS_USER,
      { is_sample: false },
    ]);
    expect(axios.post.mock.calls[1]).toEqual([
      JOB_RECENT_SCANS,
      { md5: md5("") },
    ]);
  });

  test("Recent scans - only user recent scans", async () => {
    axios.post.mockImplementation((url) => {
      switch (url) {
        case JOB_RECENT_SCANS_USER:
          return Promise.resolve({ data: recentScansUser });
        case JOB_RECENT_SCANS:
          return Promise.resolve({ data: [] });
        default:
          return Promise.reject(new Error("Error"));
      }
    });

    const { container } = render(
      <BrowserRouter>
        <RecentScans classification="generic" param="" />
      </BrowserRouter>,
    );

    await waitFor(() => {
      const recentScansTitle = screen.getByText("Recent Scans");
      expect(recentScansTitle).toBeInTheDocument();
      const recentScansInfoIcon = container.querySelector(
        "#recentscans-info-icon",
      );
      expect(recentScansInfoIcon).toBeInTheDocument();
      const recentScansTotal = screen.getByText("1 total");
      expect(recentScansTotal).toBeInTheDocument();
      // card (observable and no playbook)
      const firstCard = container.querySelector("#RecentScanCard-1");
      expect(firstCard).toBeInTheDocument();
      const firstCardTitle = screen.getByText("test.it");
      expect(firstCardTitle).toBeInTheDocument();
      expect(firstCardTitle.closest("div").className).toContain("card-header");
      // card body
      const firstCardPlaybook = screen.getByText("Playbook:");
      expect(firstCardPlaybook.textContent).toBe("Playbook: dns");
      const firstCardTLP = screen.getByText("TLP:");
      expect(firstCardTLP.textContent).toBe("TLP: AMBER");
      const firstCardUser = screen.getByText("User:");
      expect(firstCardUser.textContent).toBe("User: test");
      const firstCardFinished = screen.getByText("Finished:");
      expect(firstCardFinished).toBeInTheDocument();
    });

    // axios call
    expect(axios.post.mock.calls[0]).toEqual([
      JOB_RECENT_SCANS_USER,
      { is_sample: false },
    ]);
    expect(axios.post.mock.calls[1]).toEqual([
      JOB_RECENT_SCANS,
      { md5: md5("") },
    ]);
  });

  test("Recent scans - user and observable", async () => {
    axios.post.mockImplementation((url) => {
      switch (url) {
        case JOB_RECENT_SCANS_USER:
          return Promise.resolve({ data: recentScansUser });
        case JOB_RECENT_SCANS:
          return Promise.resolve({ data: recentScansObservable });
        default:
          return Promise.reject(new Error("Error"));
      }
    });

    const { container } = render(
      <BrowserRouter>
        <RecentScans classification="ip" param="1.2.3.4" />
      </BrowserRouter>,
    );

    await waitFor(() => {
      const recentScansTitle = screen.getByText("Recent Scans");
      expect(recentScansTitle).toBeInTheDocument();
      const recentScansInfoIcon = container.querySelector(
        "#recentscans-info-icon",
      );
      expect(recentScansInfoIcon).toBeInTheDocument();
      const recentScansTotal = screen.getByText("2 total");
      expect(recentScansTotal).toBeInTheDocument();

      // first card (file and no playbook)
      const firstCard = container.querySelector("#RecentScanCard-2");
      expect(firstCard).toBeInTheDocument();
      const firstCardTitle = screen.getByText("1.2.3.4");
      expect(firstCardTitle).toBeInTheDocument();
      expect(firstCardTitle.closest("div").className).toContain("card-header");
      const firstCardPlaybook = screen.getAllByText("Playbook:")[0];
      expect(firstCardPlaybook.textContent).toBe("Playbook: ip");
      const firstCardTLP = screen.getAllByText("TLP:")[0];
      expect(firstCardTLP.textContent).toBe("TLP: CLEAR");
      const firstCardUser = screen.getAllByText("User:")[0];
      expect(firstCardUser.textContent).toBe("User: t.test");
      const firstCardFinished = screen.getAllByText("Finished:")[0];
      expect(firstCardFinished).toBeInTheDocument();

      // second card (observable and playbook)
      const secondCard = container.querySelector("#RecentScanCard-1");
      expect(secondCard).toBeInTheDocument();
      const secondCardTitle = screen.getByText("test.it");
      expect(secondCardTitle).toBeInTheDocument();
      expect(secondCardTitle.closest("div").className).toContain("card-header");
      const secondCardPlaybook = screen.getAllByText("Playbook:")[1];
      expect(secondCardPlaybook.textContent).toBe("Playbook: dns");
      const secondCardTLP = screen.getAllByText("TLP:")[1];
      expect(secondCardTLP.textContent).toBe("TLP: AMBER");
      const secondCardUser = screen.getAllByText("User:")[1];
      expect(secondCardUser.textContent).toBe("User: test");
      const secondCardFinished = screen.getAllByText("Finished:")[1];
      expect(secondCardFinished).toBeInTheDocument();
    });

    // axios call
    expect(axios.post.mock.calls[0]).toEqual([
      JOB_RECENT_SCANS_USER,
      { is_sample: false },
    ]);
    expect(axios.post.mock.calls[1]).toEqual([
      JOB_RECENT_SCANS,
      { md5: md5("1.2.3.4") },
    ]);
  });

  test("Recent scans - redirect to job page", async () => {
    axios.post.mockImplementation((url) => {
      switch (url) {
        case JOB_RECENT_SCANS_USER:
          return Promise.resolve({ data: recentScansUser });
        case JOB_RECENT_SCANS:
          return Promise.resolve({ data: [] });
        default:
          return Promise.reject(new Error("Error"));
      }
    });

    // mock user interaction: reccomanded to put this at the start of the test
    const user = userEvent.setup();

    const { container } = render(
      <BrowserRouter>
        <RecentScans classification="generic" param="" />
      </BrowserRouter>,
    );
    await waitFor(() => {
      const recentScansTitle = screen.getByText("Recent Scans");
      expect(recentScansTitle).toBeInTheDocument();
      const recentScansInfoIcon = container.querySelector(
        "#recentscans-info-icon",
      );
      expect(recentScansInfoIcon).toBeInTheDocument();
      const recentScansTotal = screen.getByText("1 total");
      expect(recentScansTotal).toBeInTheDocument();

      // card
      const firstCard = container.querySelector("#RecentScanCard-1");
      expect(firstCard).toBeInTheDocument();
      const firstCardTitle = screen.getByText("test.it");
      expect(firstCardTitle).toBeInTheDocument();
      expect(firstCardTitle.closest("div").className).toContain("card-header");
      // card body
      const firstCardPlaybook = screen.getByText("Playbook:");
      expect(firstCardPlaybook.textContent).toBe("Playbook: dns");
      const firstCardTLP = screen.getByText("TLP:");
      expect(firstCardTLP.textContent).toBe("TLP: AMBER");
      const firstCardUser = screen.getByText("User:");
      expect(firstCardUser.textContent).toBe("User: test");
      const firstCardFinished = screen.getByText("Finished:");
      expect(firstCardFinished).toBeInTheDocument();

      // check redirect to job page
      user.click(firstCard);
    });
  });
});
