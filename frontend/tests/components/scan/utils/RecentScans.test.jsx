import React from "react";
import "@testing-library/jest-dom";
import md5 from "md5";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import {useAxiosComponentLoader, Loader} from "@certego/certego-ui";
import RecentScans from "../../../../src/components/scan/utils/RecentScans";
import {JOB_RECENT_SCANS, JOB_RECENT_SCANS_USER} from "../../../../src/constants/api";

// mock useAxiosComponentLoader 
jest.mock("@certego/certego-ui", () => {
  const originalModule = jest.requireActual("@certego/certego-ui");
  return {
    __esModule: true,
    ...originalModule,
    useAxiosComponentLoader: jest.fn()
  };
});

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
  const loaderRecentScansUser = (props) => (
    <Loader loading={false} {...props} />
  );
  const loaderRecentScans = (props) => (
    <Loader loading={false} {...props} />
  );

  test("Recent scans - default", async () => {
    // mock return value of useAxiosComponentLoader
    useAxiosComponentLoader
    .mockReturnValueOnce([[], loaderRecentScansUser])
    .mockReturnValueOnce([[], loaderRecentScans])

    render(
      <BrowserRouter>
        <RecentScans classification="generic" param="" />
      </BrowserRouter>,
    );
    const recentScansTitle = screen.getByText("Recent Scans");
    expect(recentScansTitle).toBeInTheDocument();
    const recentScansTotal = screen.getByText("0 total");
    expect(recentScansTotal).toBeInTheDocument();
    const elementText = screen.getByText("No recent scans available");
    expect(elementText).toBeInTheDocument();

    expect(useAxiosComponentLoader).toHaveBeenCalledWith({
      url: JOB_RECENT_SCANS_USER,
      method: "POST",
    });
    expect(useAxiosComponentLoader).toHaveBeenCalledWith({
      url: JOB_RECENT_SCANS,
      method: "POST",
      data: {md5: md5("")},
    });
  });

  test("Recent scans - only user recent scans", async () => {
    // mock return value of useAxiosComponentLoader
    useAxiosComponentLoader
    .mockReturnValueOnce([recentScansUser, loaderRecentScansUser])
    .mockReturnValueOnce([[], loaderRecentScans])

    const { container } = render(
      <BrowserRouter>
        <RecentScans classification="generic" param="" />
      </BrowserRouter>,
    );
    const recentScansTitle = screen.getByText("Recent Scans");
    expect(recentScansTitle).toBeInTheDocument();
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

    expect(useAxiosComponentLoader).toHaveBeenCalledWith({
      url: JOB_RECENT_SCANS_USER,
      method: "POST",
    });
    expect(useAxiosComponentLoader).toHaveBeenCalledWith({
      url: JOB_RECENT_SCANS,
      method: "POST",
      data: {md5: md5("")},
    });
  });

  test("Recent scans - user and observable", async () => {
    // mock return value of useAxiosComponentLoader
    useAxiosComponentLoader
    .mockReturnValueOnce([recentScansUser, loaderRecentScansUser])
    .mockReturnValueOnce([recentScansObservable, loaderRecentScans])

    const { container } = render(
      <BrowserRouter>
        <RecentScans classification="ip" param="1.2.3.4" />
      </BrowserRouter>,
    );
    const recentScansTitle = screen.getByText("Recent Scans");
    expect(recentScansTitle).toBeInTheDocument();
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

    expect(useAxiosComponentLoader).toHaveBeenCalledWith({
      url: JOB_RECENT_SCANS_USER,
      method: "POST",
    });
    expect(useAxiosComponentLoader).toHaveBeenCalledWith({
      url: JOB_RECENT_SCANS,
      method: "POST",
      data: {md5: md5("1.2.3.4")},
    });
  });

  test("Recent scans - redirect to job page", async () => {
    // mock return value of useAxiosComponentLoader
    useAxiosComponentLoader
    .mockReturnValueOnce([recentScansUser, loaderRecentScansUser])
    .mockReturnValueOnce([[], loaderRecentScans])
    // mock user interaction: reccomanded to put this at the start of the test
    const user = userEvent.setup();

    const { container } = render(
      <BrowserRouter>
        <RecentScans classification="generic" param="" />
      </BrowserRouter>,
    );
    const recentScansTitle = screen.getByText("Recent Scans");
    expect(recentScansTitle).toBeInTheDocument();
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

    await user.click(firstCard);
    await waitFor(() => {
      // check redirect to job page
      expect(global.location.pathname).toEqual("/jobs/1");
    });
  });
});
