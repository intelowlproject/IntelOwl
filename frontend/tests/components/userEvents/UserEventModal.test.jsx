import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import {UserEventModal} from "../../../src/components/userEvents/UserEventModal";

describe("test UserEventModal component", () => {

  const analyzableMock = {
    id: 1,
    jobs: [13],
    last_data_model: {
      id: 15,
      analyzers_report: [],
      ietf_report: [],
      evaluation: "trusted",
      reliability: 6,
      kill_chain_phase: null,
      external_references: ["test references"],
      related_threats: ["my comment"],
      tags: ["scanner"],
      malware_family: null,
      additional_info: {},
      date: "2025-05-28T10:36:04.760905Z",
      rank: null,
      resolutions: [],
    },
    name: "google.com",
    discovery_date: "2025-03-28T10:36:04.760905Z",
    md5: "1d5920f4b44b27a802bd77c4f0536f5a",
    sha256: "d4c9d9027326271a89ce51fcaf328ed673f17be33469ff979e8ab8dd501e664f",
    sha1: "baea954b95731c68ae6e45bd1e252eb4560cdc45",
    classification: "domain",
    mimetype: null,
    file: null,
  };

  test("UserEventModal - form (new evaluation)", async () => {
    const user = userEvent.setup();
    render(
      <BrowserRouter>
        <UserEventModal toggle={()=> jest.fn()} isOpen/>
      </BrowserRouter>,
    );

    const modalTitle = screen.getByRole("heading", {
      name: /Add your evaluation/i,
    });
    expect(modalTitle).toBeInTheDocument();

    const analyzablesInput = screen.getAllByRole("textbox")[0];
    expect(analyzablesInput).toBeInTheDocument();
    expect(analyzablesInput.id).toBe("analyzables-0");
    expect(screen.getByText("Type:")).toBeInTheDocument();
    expect(screen.getByText("Matches:")).toBeInTheDocument();
    expect(screen.getByText("supported only for wildcard")).toBeInTheDocument();
    const evaluationInput = screen.getByRole("combobox", { name: /Evaluation:/i });
    expect(evaluationInput).toBeInTheDocument();
    const commentsInput = screen.getAllByRole("textbox")[1];
    expect(commentsInput).toBeInTheDocument();
    expect(commentsInput.id).toBe("related_threats-0");
    const externalReferencesInput = screen.getAllByRole("textbox")[2];
    expect(externalReferencesInput).toBeInTheDocument();
    expect(externalReferencesInput.id).toBe("external_references-0");
    const killChainPhaseInput = screen.getByRole("combobox", { name: /Kill chain phase:/i });
    expect(killChainPhaseInput).toBeInTheDocument();
    expect(screen.getByText("Tags:")).toBeInTheDocument();

    // advanced fields
    const advancedFields = screen.getByRole("button", { name: /Advanced fields/i });
    expect(advancedFields).toBeInTheDocument();
    await user.click(advancedFields);
    const reliabilityInput = screen.getByText("Reliability:");
    expect(reliabilityInput).toBeInTheDocument();
    const decayTypeInput = screen.getByRole("combobox", { name: /Decay type:/i });
    expect(decayTypeInput).toBeInTheDocument();
    const decayDaysInput = screen.getByText("Decay days:");
    expect(decayDaysInput).toBeInTheDocument();

    // save button
    const saveButton = screen.getByRole("button", { name: /Save/i });
    expect(saveButton).toBeInTheDocument();
    expect(saveButton.className).toContain("disabled");
  });

  test("UserEventModal - form (add evaluation)", async () => {
    const user = userEvent.setup();
    render(
      <BrowserRouter>
        <UserEventModal analyzables={[analyzableMock]} toggle={()=> jest.fn()} isOpen/>
      </BrowserRouter>,
    );

    const modalTitle = screen.getByRole("heading", {
      name: /Add your evaluation/i,
    });
    expect(modalTitle).toBeInTheDocument();

    const analyzablesInput = screen.getAllByRole("textbox")[0];
    expect(analyzablesInput).toBeInTheDocument();
    expect(analyzablesInput.id).toBe("analyzables-0");
    expect(analyzablesInput.value).toBe("google.com");
    expect(screen.getByText("Type:")).toBeInTheDocument();
    expect(screen.getByText("artifact")).toBeInTheDocument();
    expect(screen.getByText("Matches:")).toBeInTheDocument();
    expect(screen.getByText("supported only for wildcard")).toBeInTheDocument();
    const evaluationInput = screen.getByRole("combobox", { name: /Evaluation:/i });
    expect(evaluationInput).toBeInTheDocument();
    const commentsInput = screen.getAllByRole("textbox")[1];
    expect(commentsInput).toBeInTheDocument();
    expect(commentsInput.id).toBe("related_threats-0");
    const externalReferencesInput = screen.getAllByRole("textbox")[2];
    expect(externalReferencesInput).toBeInTheDocument();
    expect(externalReferencesInput.id).toBe("external_references-0");
    const killChainPhaseInput = screen.getByRole("combobox", { name: /Kill chain phase:/i });
    expect(killChainPhaseInput).toBeInTheDocument();
    expect(screen.getByText("Tags:")).toBeInTheDocument();

    // advanced fields
    const advancedFields = screen.getByRole("button", { name: /Advanced fields/i });
    expect(advancedFields).toBeInTheDocument();
    await user.click(advancedFields);
    const reliabilityInput = screen.getByText("Reliability:");
    expect(reliabilityInput).toBeInTheDocument();
    const decayTypeInput = screen.getByRole("combobox", { name: /Decay type:/i });
    expect(decayTypeInput).toBeInTheDocument();
    const decayDaysInput = screen.getByText("Decay days:");
    expect(decayDaysInput).toBeInTheDocument();

    // save button
    const saveButton = screen.getByRole("button", { name: /Save/i });
    expect(saveButton).toBeInTheDocument();
    expect(saveButton.className).toContain("disabled");
  });
  
});
