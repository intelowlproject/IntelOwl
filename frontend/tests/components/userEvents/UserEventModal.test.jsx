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

  test.each([
    {
      title: "new evaluation",
      analyzables: [""],
      artifact: "",
    },
    {
      title: "add evaluation",
      analyzables: [analyzableMock],
      artifact: "google.com",
    },
  ])("UserEventModal - form ($title)", async ({ _, analyzables, artifact }) => {
    const user = userEvent.setup();
    render(
      <BrowserRouter>
        <UserEventModal
          analyzables={analyzables}
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
    expect(analyzablesInput.value).toBe(artifact);
    expect(screen.getByText("Type:")).toBeInTheDocument();
    expect(screen.getByText("Matches:")).toBeInTheDocument();
    expect(screen.getByText("supported only for wildcard")).toBeInTheDocument();
    expect(screen.getByText("Evaluation:")).toBeInTheDocument();
    const basicEvaluationTab = screen.getByText("Basic");
    expect(basicEvaluationTab).toBeInTheDocument();
    expect(basicEvaluationTab.closest("a").className).toContain("active"); // selected
    const advancedEvaluationTab = screen.getByText("Advanced");
    expect(advancedEvaluationTab).toBeInTheDocument();
    expect(advancedEvaluationTab.closest("a").className).not.toContain(
      "active",
    ); // selected
    const malicious10 = screen.getByRole("radio", {
      name: "Confirmed malicious",
    });
    expect(malicious10).toBeInTheDocument();
    expect(malicious10).toBeChecked();
    const malicious7 = screen.getByRole("radio", { name: "Malicious" });
    expect(malicious7).toBeInTheDocument();
    expect(malicious7).not.toBeChecked();
    const trusted8 = screen.getByRole("radio", { name: "Currently trusted" });
    expect(trusted8).toBeInTheDocument();
    expect(trusted8).not.toBeChecked();
    const trusted10 = screen.getByRole("radio", { name: "Trusted" });
    expect(trusted10).toBeInTheDocument();
    expect(trusted10).not.toBeChecked();
    const reasonInput = screen.getAllByRole("textbox")[1];
    expect(reasonInput).toBeInTheDocument();
    expect(reasonInput.id).toBe("related_threats-0");
    const externalReferencesInput = screen.getAllByRole("textbox")[2];
    expect(externalReferencesInput).toBeInTheDocument();
    expect(externalReferencesInput.id).toBe("external_references-0");
    expect(screen.getByText("Kill chain phase:")).toBeInTheDocument();
    expect(screen.getByText("Tags:")).toBeInTheDocument();

    // advanced evaluation
    await user.click(advancedEvaluationTab);
    const malicious = screen.getByRole("radio", { name: "malicious" });
    expect(malicious).toBeInTheDocument();
    expect(malicious).toBeChecked();
    const trusted = screen.getByRole("radio", { name: "trusted" });
    expect(trusted).toBeInTheDocument();
    expect(trusted).not.toBeChecked();
    expect(screen.getByText("Reliability: 10")).toBeInTheDocument();

    // advanced fields
    const advancedFields = screen.getByRole("button", {
      name: /Advanced fields/i,
    });
    expect(advancedFields).toBeInTheDocument();
    await user.click(advancedFields);
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

  const testData = {
    artifact: {
      type: "artifact",
      input: "google.com",
      getUrl: `${USER_EVENT_ANALYZABLE}?username=test&analyzable_name=google.com`,
      payload: {
        analyzable: { name: "google.com" },
        data_model_content: {
          evaluation: "malicious",
          related_threats: ["my reason"],
          reliability: 10,
        },
        decay_progression: "0",
        decay_timedelta_days: 120,
      },
    },
    ip_wildcard: {
      type: "ip wildcard",
      input: "1.2.3.0/24",
      getUrl: `${USER_EVENT_IP_WILDCARD}?username=test&network=1.2.3.0/24`,
      payload: {
        network: "1.2.3.0/24",
        data_model_content: {
          evaluation: "malicious",
          related_threats: ["my reason"],
          reliability: 10,
        },
        decay_progression: "0",
        decay_timedelta_days: 120,
      },
    },
    domain_wildcard: {
      type: "domain wildcard",
      input: ".*\\.test.com",
      getUrl: `${USER_EVENT_DOMAIN_WILDCARD}?username=test&query=.*\\.test.com`,
      payload: {
        query: ".*\\.test.com",
        data_model_content: {
          evaluation: "malicious",
          related_threats: ["my reason"],
          reliability: 10,
        },
        decay_progression: "0",
        decay_timedelta_days: 120,
      },
    },
  };

  test.each([
    // create evaluation
    {
      ...testData.artifact,
      url: USER_EVENT_ANALYZABLE,
      responseData: { count: 0 },
      eventType: "create",
    },
    {
      ...testData.ip_wildcard,
      url: USER_EVENT_IP_WILDCARD,
      responseData: { count: 0 },
      eventType: "create",
    },
    {
      ...testData.domain_wildcard,
      url: USER_EVENT_DOMAIN_WILDCARD,
      responseData: { count: 0 },
      eventType: "create",
    },
    // update evaluation
    {
      ...testData.artifact,
      url: `${USER_EVENT_ANALYZABLE}/2`,
      responseData: { count: 1, results: [{ id: 2, name: "google.com" }] },
      eventType: "update",
    },
    {
      ...testData.ip_wildcard,
      url: `${USER_EVENT_IP_WILDCARD}/2`,
      responseData: { count: 1, results: [{ id: 2, name: "google.com" }] },
      eventType: "update",
    },
    {
      ...testData.domain_wildcard,
      url: `${USER_EVENT_DOMAIN_WILDCARD}/2`,
      responseData: { count: 1, results: [{ id: 2, name: "google.com" }] },
      eventType: "update",
    },
  ])(
    "UserEventModal - $type - $eventType evaluation",
    async ({ type, input, url, getUrl, payload, responseData, eventType }) => {
      const user = userEvent.setup();
      const requestMethod = eventType === "update" ? "patch" : "post";
      axios.put.mockImplementation(() =>
        Promise.resolve({ status: 200, data: [""] }),
      );
      axios.get.mockImplementation(() =>
        Promise.resolve({ status: 200, data: responseData }),
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
      expect(screen.getByText("Evaluation:")).toBeInTheDocument();
      const basicEvaluationTab = screen.getByText("Basic");
      expect(basicEvaluationTab).toBeInTheDocument();
      expect(basicEvaluationTab.closest("a").className).toContain("active"); // selected
      const advancedEvaluationTab = screen.getByText("Advanced");
      expect(advancedEvaluationTab).toBeInTheDocument();
      expect(advancedEvaluationTab.closest("a").className).not.toContain(
        "active",
      ); // selected
      const malicious10 = screen.getByRole("radio", {
        name: "Confirmed malicious",
      });
      expect(malicious10).toBeInTheDocument();
      expect(malicious10).toBeChecked(); // selected - default
      const malicious7 = screen.getByRole("radio", { name: "Malicious" });
      expect(malicious7).toBeInTheDocument();
      expect(malicious7).not.toBeChecked();
      const trusted8 = screen.getByRole("radio", { name: "Currently trusted" });
      expect(trusted8).toBeInTheDocument();
      expect(trusted8).not.toBeChecked();
      const trusted10 = screen.getByRole("radio", { name: "Trusted" });
      expect(trusted10).toBeInTheDocument();
      expect(trusted10).not.toBeChecked();
      const reasonInput = screen.getAllByRole("textbox")[1];
      expect(reasonInput).toBeInTheDocument();
      expect(reasonInput.id).toBe("related_threats-0");
      expect(reasonInput.value).toBe("");
      const externalReferencesInput = screen.getAllByRole("textbox")[2];
      expect(externalReferencesInput).toBeInTheDocument();
      expect(externalReferencesInput.id).toBe("external_references-0");
      expect(externalReferencesInput.value).toBe("");
      expect(screen.getByText("Kill chain phase:")).toBeInTheDocument();
      expect(screen.getByText("Tags:")).toBeInTheDocument();
      const advancedFields = screen.getByRole("button", {
        name: /Advanced fields/i,
      });
      expect(advancedFields).toBeInTheDocument();
      const saveButton = screen.getByRole("button", { name: /Save/i });
      expect(saveButton).toBeInTheDocument();

      // add analyzable
      fireEvent.change(analyzablesInput, { target: { value: input } });
      expect(analyzablesInput.value).toBe(input);
      // add reason
      fireEvent.change(reasonInput, { target: { value: "my reason" } });
      expect(reasonInput.value).toBe("my reason");

      // IMPORTANT - wait for the state change
      await screen.findByText(type);

      expect(saveButton.className).not.toContain("disabled");

      await user.click(saveButton);
      await waitFor(() => {
        expect(axios.get).toHaveBeenCalledWith(`${getUrl}`);
        expect(axios[requestMethod]).toHaveBeenCalledWith(`${url}`, payload);
      });
    },
  );

  test("UserEventModal - set killchain, tags and advanced evaluation", async () => {
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
    expect(screen.getByText("supported only for wildcard")).toBeInTheDocument();
    expect(screen.getByText("Evaluation:")).toBeInTheDocument();
    const basicEvaluationTab = screen.getByText("Basic");
    expect(basicEvaluationTab).toBeInTheDocument();
    expect(basicEvaluationTab.closest("a").className).toContain("active"); // selected
    const advancedEvaluationTab = screen.getByText("Advanced");
    expect(advancedEvaluationTab).toBeInTheDocument();
    expect(advancedEvaluationTab.closest("a").className).not.toContain(
      "active",
    ); // selected
    const malicious10 = screen.getByRole("radio", {
      name: "Confirmed malicious",
    });
    expect(malicious10).toBeInTheDocument();
    expect(malicious10).toBeChecked(); // selected - default
    const malicious7 = screen.getByRole("radio", { name: "Malicious" });
    expect(malicious7).toBeInTheDocument();
    expect(malicious7).not.toBeChecked();
    const trusted8 = screen.getByRole("radio", { name: "Currently trusted" });
    expect(trusted8).toBeInTheDocument();
    expect(trusted8).not.toBeChecked();
    const trusted10 = screen.getByRole("radio", { name: "Trusted" });
    expect(trusted10).toBeInTheDocument();
    expect(trusted10).not.toBeChecked();
    const reasonInput = screen.getAllByRole("textbox")[1];
    expect(reasonInput).toBeInTheDocument();
    expect(reasonInput.id).toBe("related_threats-0");
    expect(reasonInput.value).toBe("");
    const externalReferencesInput = screen.getAllByRole("textbox")[2];
    expect(externalReferencesInput).toBeInTheDocument();
    expect(externalReferencesInput.id).toBe("external_references-0");
    const killChainPhaseInput = screen.getAllByRole("combobox")[0];
    expect(killChainPhaseInput).toBeInTheDocument();
    expect(screen.getByText("Tags:")).toBeInTheDocument();
    const tagsInput = screen.getAllByRole("combobox")[1];
    expect(tagsInput).toBeInTheDocument();
    const advancedFieldsButton = screen.getByRole("button", {
      name: /Advanced fields/i,
    });
    expect(advancedFieldsButton).toBeInTheDocument();
    await user.click(advancedEvaluationTab);
    const malicious = screen.getByRole("radio", { name: "malicious" });
    expect(malicious).toBeInTheDocument();
    expect(malicious).toBeChecked();
    const trusted = screen.getByRole("radio", { name: "trusted" });
    expect(trusted).toBeInTheDocument();
    expect(trusted).not.toBeChecked();
    expect(screen.getByText("Reliability: 10")).toBeInTheDocument();

    const saveButton = screen.getByRole("button", { name: /Save/i });
    expect(saveButton).toBeInTheDocument();
    expect(saveButton.className).toContain("disabled");

    // add analyzable
    fireEvent.change(analyzablesInput, { target: { value: "test.com" } });
    expect(analyzablesInput.value).toBe("test.com");
    // add advanced evaluation
    await user.click(trusted);
    // change reliability
    const reliabilityInput = screen.getByRole("slider");
    expect(reliabilityInput).toBeInTheDocument();
    expect(reliabilityInput.value).toBe("10");
    fireEvent.change(reliabilityInput, { target: { value: "9" } });
    expect(screen.getByText("Reliability: 9")).toBeInTheDocument();
    // add reason
    fireEvent.change(reasonInput, { target: { value: "my reason" } });
    expect(reasonInput.value).toBe("my reason");
    // add tags (2 of them)
    await userEvent.click(tagsInput);
    await userEvent.click(screen.getByText("phishing"));
    expect(screen.getByText("phishing")).toBeInTheDocument();
    expect(screen.queryByText("malware")).not.toBeInTheDocument(); // check other option are not visible
    await userEvent.click(tagsInput);
    await userEvent.click(screen.getByText("malware"));
    expect(screen.getByText("malware")).toBeInTheDocument();
    expect(screen.queryByText("abused")).not.toBeInTheDocument(); // check other option are not visible
    // add kill chain phase
    await userEvent.click(killChainPhaseInput);
    await userEvent.click(screen.getByText("action"));
    expect(screen.getByText("action")).toBeInTheDocument();
    expect(screen.queryByText("c2")).not.toBeInTheDocument(); // check other option are not visible

    // IMPORTANT - wait for the state change
    await screen.findByText("artifact");

    expect(saveButton.className).not.toContain("disabled");

    await user.click(saveButton);
    await waitFor(() => {
      expect(axios.get).toHaveBeenCalledWith(
        `${`${USER_EVENT_ANALYZABLE}?username=test&analyzable_name=test.com`}`,
      );
      expect(axios.post).toHaveBeenCalledWith(`${USER_EVENT_ANALYZABLE}`, {
        analyzable: { name: "test.com" },
        data_model_content: {
          evaluation: "trusted",
          related_threats: ["my reason"],
          reliability: "9",
          kill_chain_phase: "action",
          tags: ["phishing", "malware"],
        },
        decay_progression: "0",
        decay_timedelta_days: 120,
      });
    });
  });

  test("UserEventModal - advanced --> basic evaluation", async () => {
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
    expect(screen.getByText("supported only for wildcard")).toBeInTheDocument();
    expect(screen.getByText("Evaluation:")).toBeInTheDocument();
    const basicEvaluationTab = screen.getByText("Basic");
    expect(basicEvaluationTab).toBeInTheDocument();
    expect(basicEvaluationTab.closest("a").className).toContain("active"); // selected
    const advancedEvaluationTab = screen.getByText("Advanced");
    expect(advancedEvaluationTab).toBeInTheDocument();
    expect(advancedEvaluationTab.closest("a").className).not.toContain(
      "active",
    ); // selected
    const malicious10 = screen.getByRole("radio", {
      name: "Confirmed malicious",
    });
    expect(malicious10).toBeInTheDocument();
    expect(malicious10).toBeChecked(); // selected - default
    const malicious7 = screen.getByRole("radio", { name: "Malicious" });
    expect(malicious7).toBeInTheDocument();
    expect(malicious7).not.toBeChecked();
    const trusted8 = screen.getByRole("radio", { name: "Currently trusted" });
    expect(trusted8).toBeInTheDocument();
    expect(trusted8).not.toBeChecked();
    const trusted10 = screen.getByRole("radio", { name: "Trusted" });
    expect(trusted10).toBeInTheDocument();
    expect(trusted10).not.toBeChecked();
    const reasonInput = screen.getAllByRole("textbox")[1];
    expect(reasonInput).toBeInTheDocument();
    expect(reasonInput.id).toBe("related_threats-0");
    expect(reasonInput.value).toBe("");
    const externalReferencesInput = screen.getAllByRole("textbox")[2];
    expect(externalReferencesInput).toBeInTheDocument();
    expect(externalReferencesInput.id).toBe("external_references-0");
    const killChainPhaseInput = screen.getAllByRole("combobox")[0];
    expect(killChainPhaseInput).toBeInTheDocument();
    expect(screen.getByText("Tags:")).toBeInTheDocument();
    const tagsInput = screen.getAllByRole("combobox")[1];
    expect(tagsInput).toBeInTheDocument();
    const advancedFieldsButton = screen.getByRole("button", {
      name: /Advanced fields/i,
    });
    expect(advancedFieldsButton).toBeInTheDocument();
    await user.click(advancedEvaluationTab);
    const malicious = screen.getByRole("radio", { name: "malicious" });
    expect(malicious).toBeInTheDocument();
    expect(malicious).toBeChecked();
    const trusted = screen.getByRole("radio", { name: "trusted" });
    expect(trusted).toBeInTheDocument();
    expect(trusted).not.toBeChecked();
    expect(screen.getByText("Reliability: 10")).toBeInTheDocument();

    const saveButton = screen.getByRole("button", { name: /Save/i });
    expect(saveButton).toBeInTheDocument();
    expect(saveButton.className).toContain("disabled");

    // add analyzable
    fireEvent.change(analyzablesInput, { target: { value: "test.com" } });
    expect(analyzablesInput.value).toBe("test.com");
    // set advanced evaluation
    await user.click(trusted);
    // change reliability
    const reliabilityInput = screen.getByRole("slider");
    expect(reliabilityInput).toBeInTheDocument();
    expect(reliabilityInput.value).toBe("10");
    fireEvent.change(reliabilityInput, { target: { value: "9" } });
    expect(screen.getByText("Reliability: 9")).toBeInTheDocument();
    // add reason
    fireEvent.change(reasonInput, { target: { value: "my reason" } });
    expect(reasonInput.value).toBe("my reason");
    // basic evaluation tab
    await user.click(basicEvaluationTab);
    const advancedEvalWarning = screen.getByText(
      "Advanced reliability has been set and save correctly. Selecting a new basic evaluation will overwrite the previous settings.",
    );
    expect(advancedEvalWarning).toBeInTheDocument();
    // set advanced evaluation
    await user.click(malicious7);
    expect(advancedEvalWarning).not.toBeInTheDocument();

    // IMPORTANT - wait for the state change
    await screen.findByText("artifact");

    expect(saveButton.className).not.toContain("disabled");

    await user.click(saveButton);
    await waitFor(() => {
      expect(axios.get).toHaveBeenCalledWith(
        `${`${USER_EVENT_ANALYZABLE}?username=test&analyzable_name=test.com`}`,
      );
      expect(axios.post).toHaveBeenCalledWith(`${USER_EVENT_ANALYZABLE}`, {
        analyzable: { name: "test.com" },
        data_model_content: {
          evaluation: "malicious",
          related_threats: ["my reason"],
          reliability: 7,
        },
        decay_progression: "0",
        decay_timedelta_days: 120,
      });
    });
  });
});
