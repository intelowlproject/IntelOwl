import React from "react";
import axios from "axios";
import "@testing-library/jest-dom";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import { UserEventModal } from "../../../src/components/userEvents/UserEventModal";
import {
  USER_EVENT_ANALYZABLE,
  USER_EVENT_IP_WILDCARD,
  USER_EVENT_DOMAIN_WILDCARD,
} from "../../../src/constants/apiURLs";
import { mockedUseTagsStore, mockedUseAuthStore } from "../../mock";

jest.mock("axios");
jest.mock("../../../src/stores/useAuthStore", () => ({
  useAuthStore: jest.fn((state) => state(mockedUseAuthStore)),
}));
jest.mock("../../../src/stores/useTagsStore", () => ({
  useTagsStore: jest.fn((state) => state(mockedUseTagsStore)),
}));

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
        <UserEventModal toggle={() => jest.fn()} isOpen />
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
    const evaluationInput = screen.getByRole("combobox", {
      name: /Evaluation:/i,
    });
    expect(evaluationInput).toBeInTheDocument();
    const commentsInput = screen.getAllByRole("textbox")[1];
    expect(commentsInput).toBeInTheDocument();
    expect(commentsInput.id).toBe("related_threats-0");
    const externalReferencesInput = screen.getAllByRole("textbox")[2];
    expect(externalReferencesInput).toBeInTheDocument();
    expect(externalReferencesInput.id).toBe("external_references-0");
    const killChainPhaseInput = screen.getByRole("combobox", {
      name: /Kill chain phase:/i,
    });
    expect(killChainPhaseInput).toBeInTheDocument();
    expect(screen.getByText("Tags:")).toBeInTheDocument();

    // advanced fields
    const advancedFields = screen.getByRole("button", {
      name: /Advanced fields/i,
    });
    expect(advancedFields).toBeInTheDocument();
    await user.click(advancedFields);
    const reliabilityInput = screen.getByText("Reliability:");
    expect(reliabilityInput).toBeInTheDocument();
    const decayTypeInput = screen.getByRole("combobox", {
      name: /Decay type:/i,
    });
    expect(decayTypeInput).toBeInTheDocument();
    const decayDaysInput = screen.getByText("Decay days:");
    expect(decayDaysInput).toBeInTheDocument();

    // save button
    const saveButton = screen.getByRole("button", { name: /Save/i });
    expect(saveButton).toBeInTheDocument();
    expect(saveButton.className).toContain("disabled");
  });

  test.each([
    {
      type: "artifact",
      input: "google.com",
      url: USER_EVENT_ANALYZABLE,
      getUrl: `${USER_EVENT_ANALYZABLE}?username=test&analyzable_name=google.com`,
      payload: {
        analyzable: { name: "google.com" },
        data_model_content: {
          evaluation: "malicious",
          related_threats: ["my comment"],
          reliability: 10,
        },
        decay_progression: "0",
        decay_timedelta_days: 120,
      },
    },
    {
      type: "ip wildcard",
      input: "1.2.3.0/24",
      url: USER_EVENT_IP_WILDCARD,
      getUrl: `${USER_EVENT_IP_WILDCARD}?username=test&network=1.2.3.0/24`,
      payload: {
        network: "1.2.3.0/24",
        data_model_content: {
          evaluation: "malicious",
          related_threats: ["my comment"],
          reliability: 10,
        },
        decay_progression: "0",
        decay_timedelta_days: 120,
      },
    },
    {
      type: "domain wildcard",
      input: ".*\\.test.com",
      url: USER_EVENT_DOMAIN_WILDCARD,
      getUrl: `${USER_EVENT_DOMAIN_WILDCARD}?username=test&query=.*\\.test.com`,
      payload: {
        query: ".*\\.test.com",
        data_model_content: {
          evaluation: "malicious",
          related_threats: ["my comment"],
          reliability: 10,
        },
        decay_progression: "0",
        decay_timedelta_days: 120,
      },
    },
  ])(
    "UserEventModal - $type (new evaluation) - create event",
    async ({ type, input, url, getUrl, payload }) => {
      const user = userEvent.setup();
      axios.put.mockImplementation(() =>
        Promise.resolve({ status: 200, data: [""] }),
      );
      axios.get.mockImplementation(() =>
        Promise.resolve({ status: 200, data: { count: 0 } }),
      );
      render(
        <BrowserRouter>
          <UserEventModal toggle={() => jest.fn()} isOpen />
        </BrowserRouter>,
      );

      const modalTitle = screen.getByRole("heading", {
        name: /Add your evaluation/i,
      });
      expect(modalTitle).toBeInTheDocument();

      const analyzablesInput = screen.getAllByRole("textbox")[0];
      expect(analyzablesInput).toBeInTheDocument();
      expect(analyzablesInput.id).toBe("analyzables-0");
      expect(analyzablesInput.value).toBe("");
      expect(screen.getByText("Type:")).toBeInTheDocument();
      expect(screen.getByText("Matches:")).toBeInTheDocument();
      expect(
        screen.getByText("supported only for wildcard"),
      ).toBeInTheDocument();
      const evaluationInput = screen.getByRole("combobox", {
        name: /Evaluation:/i,
      });
      expect(evaluationInput).toBeInTheDocument();
      const commentsInput = screen.getAllByRole("textbox")[1];
      expect(commentsInput).toBeInTheDocument();
      expect(commentsInput.id).toBe("related_threats-0");
      expect(commentsInput.value).toBe("");
      const externalReferencesInput = screen.getAllByRole("textbox")[2];
      expect(externalReferencesInput).toBeInTheDocument();
      expect(externalReferencesInput.id).toBe("external_references-0");
      const killChainPhaseInput = screen.getByRole("combobox", {
        name: /Kill chain phase:/i,
      });
      expect(killChainPhaseInput).toBeInTheDocument();
      expect(screen.getByText("Tags:")).toBeInTheDocument();
      const advancedFields = screen.getByRole("button", {
        name: /Advanced fields/i,
      });
      expect(advancedFields).toBeInTheDocument();
      const saveButton = screen.getByRole("button", { name: /Save/i });
      expect(saveButton).toBeInTheDocument();
      expect(saveButton.className).toContain("disabled");

      // add analyzable
      fireEvent.change(analyzablesInput, { target: { value: input } });
      expect(analyzablesInput.value).toBe(input);
      // add evaluation
      fireEvent.change(evaluationInput, { target: { value: "malicious" } });
      expect(screen.getByText("MALICIOUS")).toBeInTheDocument();
      // add comment
      fireEvent.change(commentsInput, { target: { value: "my comment" } });
      expect(commentsInput.value).toBe("my comment");

      // IMPORTANT - wait for the state change
      await screen.findByText(type);

      expect(saveButton.className).not.toContain("disabled");

      await user.click(saveButton);
      await waitFor(() => {
        expect(axios.get).toHaveBeenCalledWith(`${getUrl}`);
        expect(axios.post).toHaveBeenCalledWith(`${url}`, payload);
      });
    },
  );

  test.each([
    {
      type: "artifact",
      input: "google.com",
      url: USER_EVENT_ANALYZABLE,
      getUrl: `${USER_EVENT_ANALYZABLE}?username=test&analyzable_name=google.com`,
      payload: {
        analyzable: { name: "google.com" },
        data_model_content: {
          evaluation: "malicious",
          related_threats: ["my comment"],
          reliability: 10,
        },
        decay_progression: "0",
        decay_timedelta_days: 120,
      },
    },
    {
      type: "ip wildcard",
      input: "1.2.3.0/24",
      url: USER_EVENT_IP_WILDCARD,
      getUrl: `${USER_EVENT_IP_WILDCARD}?username=test&network=1.2.3.0/24`,
      payload: {
        network: "1.2.3.0/24",
        data_model_content: {
          evaluation: "malicious",
          related_threats: ["my comment"],
          reliability: 10,
        },
        decay_progression: "0",
        decay_timedelta_days: 120,
      },
    },
    {
      type: "domain wildcard",
      input: ".*\\.test.com",
      url: USER_EVENT_DOMAIN_WILDCARD,
      getUrl: `${USER_EVENT_DOMAIN_WILDCARD}?username=test&query=.*\\.test.com`,
      payload: {
        query: ".*\\.test.com",
        data_model_content: {
          evaluation: "malicious",
          related_threats: ["my comment"],
          reliability: 10,
        },
        decay_progression: "0",
        decay_timedelta_days: 120,
      },
    },
  ])(
    "UserEventModal - $type (new evaluation) - update event",
    async ({ type, input, url, getUrl, payload }) => {
      const user = userEvent.setup();
      axios.put.mockImplementation(() =>
        Promise.resolve({ status: 200, data: [""] }),
      );
      axios.get.mockImplementation(() =>
        Promise.resolve({
          status: 200,
          data: { count: 1, results: [{ id: 2, name: "google.com" }] },
        }),
      );
      render(
        <BrowserRouter>
          <UserEventModal toggle={() => jest.fn()} isOpen />
        </BrowserRouter>,
      );

      const modalTitle = screen.getByRole("heading", {
        name: /Add your evaluation/i,
      });
      expect(modalTitle).toBeInTheDocument();

      const analyzablesInput = screen.getAllByRole("textbox")[0];
      expect(analyzablesInput).toBeInTheDocument();
      expect(analyzablesInput.id).toBe("analyzables-0");
      expect(analyzablesInput.value).toBe("");
      expect(screen.getByText("Type:")).toBeInTheDocument();
      expect(screen.getByText("Matches:")).toBeInTheDocument();
      expect(
        screen.getByText("supported only for wildcard"),
      ).toBeInTheDocument();
      const evaluationInput = screen.getByRole("combobox", {
        name: /Evaluation:/i,
      });
      expect(evaluationInput).toBeInTheDocument();
      const commentsInput = screen.getAllByRole("textbox")[1];
      expect(commentsInput).toBeInTheDocument();
      expect(commentsInput.id).toBe("related_threats-0");
      expect(commentsInput.value).toBe("");
      const externalReferencesInput = screen.getAllByRole("textbox")[2];
      expect(externalReferencesInput).toBeInTheDocument();
      expect(externalReferencesInput.id).toBe("external_references-0");
      const killChainPhaseInput = screen.getByRole("combobox", {
        name: /Kill chain phase:/i,
      });
      expect(killChainPhaseInput).toBeInTheDocument();
      expect(screen.getByText("Tags:")).toBeInTheDocument();
      const advancedFields = screen.getByRole("button", {
        name: /Advanced fields/i,
      });
      expect(advancedFields).toBeInTheDocument();
      const saveButton = screen.getByRole("button", { name: /Save/i });
      expect(saveButton).toBeInTheDocument();
      expect(saveButton.className).toContain("disabled");

      /// add analyzable
      fireEvent.change(analyzablesInput, { target: { value: input } });
      expect(analyzablesInput.value).toBe(input);
      // add evaluation
      fireEvent.change(evaluationInput, { target: { value: "malicious" } });
      expect(screen.getByText("MALICIOUS")).toBeInTheDocument();
      // add comment
      fireEvent.change(commentsInput, { target: { value: "my comment" } });
      expect(commentsInput.value).toBe("my comment");

      // IMPORTANT - wait for the state change
      await screen.findByText(type);

      expect(saveButton.className).not.toContain("disabled");
      await user.click(saveButton);

      await waitFor(() => {
        expect(axios.get).toHaveBeenCalledWith(`${getUrl}`);
        expect(axios.patch).toHaveBeenCalledWith(`${url}/2`, payload);
      });
    },
  );

  test("UserEventModal - form (add evaluation)", async () => {
    const user = userEvent.setup();
    render(
      <BrowserRouter>
        <UserEventModal
          analyzables={[analyzableMock]}
          toggle={() => jest.fn()}
          isOpen
        />
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
    const evaluationInput = screen.getByRole("combobox", {
      name: /Evaluation:/i,
    });
    expect(evaluationInput).toBeInTheDocument();
    const commentsInput = screen.getAllByRole("textbox")[1];
    expect(commentsInput).toBeInTheDocument();
    expect(commentsInput.id).toBe("related_threats-0");
    const externalReferencesInput = screen.getAllByRole("textbox")[2];
    expect(externalReferencesInput).toBeInTheDocument();
    expect(externalReferencesInput.id).toBe("external_references-0");
    const killChainPhaseInput = screen.getByRole("combobox", {
      name: /Kill chain phase:/i,
    });
    expect(killChainPhaseInput).toBeInTheDocument();
    expect(screen.getByText("Tags:")).toBeInTheDocument();

    // advanced fields
    const advancedFields = screen.getByRole("button", {
      name: /Advanced fields/i,
    });
    expect(advancedFields).toBeInTheDocument();
    await user.click(advancedFields);
    const reliabilityInput = screen.getByText("Reliability:");
    expect(reliabilityInput).toBeInTheDocument();
    const decayTypeInput = screen.getByRole("combobox", {
      name: /Decay type:/i,
    });
    expect(decayTypeInput).toBeInTheDocument();
    const decayDaysInput = screen.getByText("Decay days:");
    expect(decayDaysInput).toBeInTheDocument();

    // save button
    const saveButton = screen.getByRole("button", { name: /Save/i });
    expect(saveButton).toBeInTheDocument();
    expect(saveButton.className).toContain("disabled");
  });
});
