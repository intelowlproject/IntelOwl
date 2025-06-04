import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import { AnalyzableOverview } from "../../../../src/components/analyzables/result/AnalyzableOverview";

describe("test AnalyzableOverview", () => {
    const analyzableMock = {
        id: 1,
        jobs: [
          {
            playbook: "Dns",
            id: 13,
            user: {
              username: "admin",
                // ...
            },
            date: "2025-05-27T14:05:34.542462Z",
            data_model: {
              id: 14,
              analyzers_report: [],
              ietf_report: [],
              evaluation: null,
              reliability: 5,
              kill_chain_phase: null,
              external_references: [],
              related_threats: [],
              tags: null,
              malware_family: null,
              additional_info: {},
              date: "2025-05-27T14:05:34.398314Z",
              rank: null,
              resolutions: []
            }
          }
        ],
        user_events: [
          {
            id: 6,
            user: {
              "username": "admin",
              // ...
            },
            date: "2025-05-28T10:36:04.762720Z",
            next_decay: "2025-06-03T10:36:04.762720Z",
            decay_times: 1,
            analyzable: 2,
            data_model: {
              id: 15,
              analyzers_report: [],
              ietf_report: [],
              evaluation: "malicious",
              reliability: 6,
              kill_chain_phase: null,
              external_references: ["test references"],
              related_threats: ["my comment"],
              tags: ["scanner"],
              malware_family: null,
              additional_info: {},
              date: "2025-05-28T10:36:04.760905Z",
              rank: null,
              resolutions: []
            },
            data_model_object_id: 15,
            decay_progression: 0,
            decay_timedelta_days: 3,
            data_model_content_type: 44
          }
        ],
        name: "google.com",
        discovery_date: "2025-05-05T12:55:43.777042Z",
        md5: "1d5920f4b44b27a802bd77c4f0536f5a",
        sha256:
          "d4c9d9027326271a89ce51fcaf328ed673f17be33469ff979e8ab8dd501e664f",
        sha1: "baea954b95731c68ae6e45bd1e252eb4560cdc45",
        classification: "domain",
        mimetype: null,
        file: null,
      };

  test("AnalyzableOverview components", async () => {
    const user = userEvent.setup();
    const { container } = render(
      <BrowserRouter>
        <AnalyzableOverview
          analyzable={analyzableMock}
        />
      </BrowserRouter>,
    );
    // Page title
    expect(
      screen.getByRole("heading", { name: "Analyzable #1" }),
    ).toBeInTheDocument();
    // buttons
    const rescanButton = screen.getByRole("link", { name: "Rescan" });
    expect(rescanButton).toBeInTheDocument();
    expect(rescanButton.href).toContain("/scan?observable=google.com");
    // name
    expect(
      screen.getByRole("heading", { name: "google.com" }),
    ).toBeInTheDocument();
    // classification badge
    expect(screen.getByText("domain")).toBeInTheDocument();
    // toggle info icon
    const toggleIcon = container.querySelector("#AnalyzableInfoCardDropDown");
    expect(toggleIcon).toBeInTheDocument();
    await user.click(toggleIcon);
    expect(screen.getByText("SHA256")).toBeInTheDocument();
    expect(screen.getByText("SHA1")).toBeInTheDocument();
    expect(screen.getByText("MD5")).toBeInTheDocument();
    // visualizers - first row
    expect(screen.getByText("First Analysis")).toBeInTheDocument();
    expect(screen.getByText("Last Evaluation")).toBeInTheDocument();
    expect(screen.getByText("Last Evaluation Date")).toBeInTheDocument();
    expect(screen.getByText("Decay")).toBeInTheDocument();
    expect(screen.getByText("Malware Family")).toBeInTheDocument();
    expect(screen.getByText("Killchain Phase")).toBeInTheDocument();
    // visualizers - second row
    expect(screen.getByText("Tags (1)")).toBeInTheDocument();
    expect(screen.getByText("scanner")).toBeInTheDocument();
    expect(screen.getByText("External References (1)")).toBeInTheDocument();
    expect(screen.getByText("test references")).toBeInTheDocument();
    expect(screen.getByText("Comments (1)")).toBeInTheDocument();
    expect(screen.getAllByText("my comment")[0]).toBeInTheDocument();

    // History
    expect(
        screen.getByRole("heading", { name: "History" }),
    ).toBeInTheDocument();
    // column headers
    expect(
        screen.getByRole("columnheader", { name: "ID" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("columnheader", { name: "User" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("columnheader", { name: "Date" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("columnheader", { name: "Type All" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("columnheader", { name: "Evaluation" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("columnheader", { name: "Tags" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("columnheader", { name: "Description" }),
    ).toBeInTheDocument();
    // cells
    expect(
        screen.getByRole("cell", { name: "#13" }),
    ).toBeInTheDocument();
    expect(screen.getByText("#13").href).toContain("/jobs/13/visualizer");
    expect(
        screen.getAllByRole("cell", { name: "admin" })[0],
    ).toBeInTheDocument();
    expect(
        screen.getByRole("cell", { name: "job" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("cell", { name: "Playbook executed: Dns" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("cell", { name: "#6" }),
    ).toBeInTheDocument();
    expect(screen.getByText("#6").href).toContain("/analyzables/6");
    expect(
        screen.getAllByRole("cell", { name: "admin" })[1],
    ).toBeInTheDocument();
    expect(
        screen.getByRole("cell", { name: "user report" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("cell", { name: "MALICIOUS" }),
    ).toBeInTheDocument();
    const scannerBadge = container.querySelector("#tag__row1_0");
    expect(scannerBadge).toBeInTheDocument();
    expect(
        screen.getByRole("cell", { name: "my comment" }),
    ).toBeInTheDocument();
  });
});
