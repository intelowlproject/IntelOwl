import React from "react";
import "@testing-library/jest-dom";
import { render, within } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import { InvestigationInfoCard } from "../../../../src/components/investigations/result/InvestigationInfoCard";

describe("test InvestigationInfoCard (investigation report)", () => {
  test("metadata section", () => {
    const { container } = render(
      <BrowserRouter>
        <InvestigationInfoCard
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
        />
      </BrowserRouter>,
    );

    // metadata
    const InfoCardSection = container.querySelector(
      "#InvestigationInfoCardSection",
    );
    expect(within(InfoCardSection).getByText("My test")).toBeInTheDocument();
    const editNameButton = container.querySelector("#edit-investigation-name");
    expect(editNameButton).toBeInTheDocument();
    const InfoCardDropDown = container.querySelector(
      "#InvestigationInfoCardDropDown",
    );
    expect(InfoCardDropDown).toBeInTheDocument();
    expect(within(InfoCardSection).getByText("Status")).toBeInTheDocument();
    expect(within(InfoCardSection).getByText("CONCLUDED")).toBeInTheDocument();
    expect(within(InfoCardSection).getByText("TLP")).toBeInTheDocument();
    expect(within(InfoCardSection).getByText("Start Time")).toBeInTheDocument();
    expect(
      within(InfoCardSection).getByText("08:19:03 AM May 6th, 2024"),
    ).toBeInTheDocument();
  });
});
