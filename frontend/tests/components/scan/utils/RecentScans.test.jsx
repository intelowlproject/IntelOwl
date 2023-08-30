import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import RecentScans from "../../../../src/components/scan/utils/RecentScans";

jest.mock("@certego/certego-ui", () => {
  const originalModule = jest.requireActual("@certego/certego-ui");
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
  const recentScans = [
    {
      file_name: "test.json",
      finished_analysis_time: "2023-08-25T15:43:13.896626Z",
      importance: 5,
      observable_name: "",
      pk: 2,
      playbook: null,
      tlp: "CLEAR",
      user: "t.test",
    },
  ];
  const loaderRecentScansUser = (props) => (
    <originalModule.Loader loading={false} {...props} />
  );
  const loaderRecentScans = (props) => (
    <originalModule.Loader loading={false} {...props} />
  );

  // mock useAxiosComponentLoader
  return {
    __esModule: true,
    ...originalModule,
    useAxiosComponentLoader: jest.fn()
      // mock for 'Recent scans - no recent scans' test
      .mockReturnValueOnce([[], loaderRecentScansUser])
      .mockReturnValueOnce([[], loaderRecentScans])
      // mock for 'Recent scans - only user recent scans' test
      .mockReturnValueOnce([recentScansUser, loaderRecentScansUser])
      .mockReturnValueOnce([[], loaderRecentScans])
      // mock for 'Recent scans - user and observable' test
      .mockReturnValueOnce([recentScansUser, loaderRecentScansUser])
      .mockReturnValueOnce([recentScans, loaderRecentScans])
      // mock for 'Recent scans - redirect to job page' test
      .mockReturnValueOnce([recentScansUser, loaderRecentScansUser])
      .mockReturnValueOnce([[], loaderRecentScans])
  };
});


describe("Recent Scans test", () => {
  test("Recent scans - no recent scans", async () => {
    render(
      <BrowserRouter>
        <RecentScans classification={jest.fn()} param={jest.fn()} />
      </BrowserRouter>,
    );
    const recentScansTitle = screen.getByText("Recent Scans");
    expect(recentScansTitle).toBeInTheDocument();
    const recentScans = screen.getByText("0 total");
    expect(recentScans).toBeInTheDocument();
    const elementText = screen.getByText("No recent scans available");
    expect(elementText).toBeInTheDocument();
  });

  test("Recent scans - only user recent scans", async () => {
    const { container } = render(
      <BrowserRouter>
        <RecentScans classification={jest.fn()} param={jest.fn()} />
      </BrowserRouter>,
    );
    const recentScansTitle = screen.getByText("Recent Scans");
    expect(recentScansTitle).toBeInTheDocument();
    const recentScans = screen.getByText("1 total");
    expect(recentScans).toBeInTheDocument();
    
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

  test("Recent scans - user and observable", async () => {
    const { container } = render(
      <BrowserRouter>
        <RecentScans classification={jest.fn()} param={jest.fn()} />
      </BrowserRouter>,
    );
    const recentScansTitle = screen.getByText("Recent Scans");
    expect(recentScansTitle).toBeInTheDocument();
    const recentScans = screen.getByText("2 total");
    expect(recentScans).toBeInTheDocument();
    
    // first card (file and no playbook)
    const firstCard = container.querySelector("#RecentScanCard-2");
    expect(firstCard).toBeInTheDocument();
    const firstCardTitle = screen.getByText("test.json");
    expect(firstCardTitle).toBeInTheDocument();
    expect(firstCardTitle.closest("div").className).toContain("card-header");
    const firstCardPlaybook = screen.getAllByText("Playbook:")[0];
    expect(firstCardPlaybook.textContent).toBe("Playbook: Custom analysis");
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

  test("Recent scans - redirect to job page", async () => {
    // mock user interaction: reccomanded to put this at the start of the test
    const user = userEvent.setup();

    const { container } = render(
      <BrowserRouter>
        <RecentScans classification={jest.fn()} param={jest.fn()} />
      </BrowserRouter>,
    );
    const recentScansTitle = screen.getByText("Recent Scans");
    expect(recentScansTitle).toBeInTheDocument();
    const recentScans = screen.getByText("1 total");
    expect(recentScans).toBeInTheDocument();
    
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
