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
    axios.get.mockImplementation(() =>
      Promise.resolve({ status: 200, data: { count: 0 } }),
    );
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
    expect(screen.getByText("Evaluation:")).toBeInTheDocument();
    const excludeEvaluation = screen.getByRole("checkbox", {
      id: "exclude-evaluation-flag",
    });
    expect(excludeEvaluation).toBeInTheDocument();
    expect(excludeEvaluation).not.toBeChecked();
    const basicEvaluationTab = screen.getByText("Basic");
    expect(basicEvaluationTab).toBeInTheDocument();
    expect(basicEvaluationTab.closest("a").className).toContain("active"); // selected
    const manualEvaluationTab = screen.getByText("Manual");
    expect(manualEvaluationTab).toBeInTheDocument();
    expect(manualEvaluationTab.closest("a").className).not.toContain("active"); // selected
    const malicious10 = screen.getByRole("button", {
      name: "Confirmed malicious",
    });
    expect(malicious10).toBeInTheDocument();
    expect(malicious10.className).toContain("active"); // selected
    const malicious7 = screen.getByRole("button", { name: "Malicious" });
    expect(malicious7).toBeInTheDocument();
    expect(malicious7.className).not.toContain("active");
    const trusted8 = screen.getByRole("button", { name: "Currently trusted" });
    expect(trusted8).toBeInTheDocument();
    expect(trusted8.className).not.toContain("active");
    const trusted10 = screen.getByRole("button", { name: "Trusted" });
    expect(trusted10).toBeInTheDocument();
    expect(trusted10.className).not.toContain("active");
    const reasonInput = screen.getAllByRole("textbox")[1];
    expect(reasonInput).toBeInTheDocument();
    expect(reasonInput.id).toBe("reason");
    expect(reasonInput.value).toBe("");
    const malwareFamilyInput = screen.getAllByRole("textbox")[2];
    expect(malwareFamilyInput).toBeInTheDocument();
    expect(malwareFamilyInput.id).toBe("malware_family");
    expect(malwareFamilyInput.value).toBe("");
    const relatedThreatsInput = screen.getAllByRole("textbox")[3];
    expect(relatedThreatsInput).toBeInTheDocument();
    expect(relatedThreatsInput.id).toBe("related_threats-0");
    expect(relatedThreatsInput.value).toBe("");
    const externalReferencesInput = screen.getAllByRole("textbox")[4];
    expect(externalReferencesInput).toBeInTheDocument();
    expect(externalReferencesInput.id).toBe("external_references-0");
    expect(screen.getByText("Kill chain phase:")).toBeInTheDocument();
    expect(screen.getByText("Tags:")).toBeInTheDocument();

    // your evaluations section
    expect(screen.getByText("Your evaluations:")).toBeInTheDocument();

    // manual evaluation
    await user.click(manualEvaluationTab);
    const malicious = screen.getByRole("button", { name: "malicious" });
    expect(malicious).toBeInTheDocument();
    expect(malicious.className).toContain("active");
    const trusted = screen.getByRole("button", { name: "trusted" });
    expect(trusted).toBeInTheDocument();
    expect(trusted.className).not.toContain("active");
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

  const dataModelContent = {
    evaluation: "malicious",
    reliability: 10,
    malware_family: "",
    kill_chain_phase: "",
    related_threats: [],
    external_references: [],
    tags: [],
  };

  const testData = {
    artifact: {
      type: "artifact",
      input: "google.com",
      getUrl: `${USER_EVENT_ANALYZABLE}?username=test&analyzable_name=google.com`,
      payload: {
        analyzable: { name: "google.com" },
        data_model_content: dataModelContent,
        reason: "my reason",
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
        data_model_content: dataModelContent,
        reason: "my reason",
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
        data_model_content: dataModelContent,
        reason: "my reason",
        decay_progression: "0",
        decay_timedelta_days: 120,
      },
    },
  };

  const dataModelExistingEvent = {
    evaluation: "trusted",
    reliability: 8,
    malware_family: "",
    kill_chain_phase: "",
    related_threats: [],
    external_references: [],
    tags: [],
    date: "2026-03-17T15:01:13.054478Z",
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
      responseData: {
        count: 1,
        results: [
          { id: 2, analyzable: { id: 1 }, data_model: dataModelExistingEvent },
        ],
      },
      eventType: "update",
    },
    {
      ...testData.ip_wildcard,
      url: `${USER_EVENT_IP_WILDCARD}/2`,
      responseData: {
        count: 1,
        results: [
          { id: 2, analyzables: [2], data_model: dataModelExistingEvent },
        ],
      },
      eventType: "update",
    },
    {
      ...testData.domain_wildcard,
      url: `${USER_EVENT_DOMAIN_WILDCARD}/2`,
      responseData: {
        count: 1,
        results: [
          { id: 2, analyzables: [1], data_model: dataModelExistingEvent },
        ],
      },
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

      const analyzablesInput = screen.getAllByRole("textbox")[0];
      expect(analyzablesInput).toBeInTheDocument();
      expect(analyzablesInput.id).toBe("analyzables-0");
      expect(analyzablesInput.value).toBe("");

      const basicEvaluationTab = screen.getByText("Basic");
      expect(basicEvaluationTab).toBeInTheDocument();
      expect(basicEvaluationTab.closest("a").className).toContain("active"); // selected

      const reasonInput = screen.getAllByRole("textbox")[1];
      expect(reasonInput).toBeInTheDocument();
      expect(reasonInput.id).toBe("reason");
      expect(reasonInput.value).toBe("");

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
      await waitFor(() => {
        expect(axios.get).toHaveBeenCalledWith(`${getUrl}`);
      });

      expect(saveButton.className).not.toContain("disabled");
      await user.click(saveButton);
      if (eventType === "update") {
        // confirm dialog
        const confirmButton = screen.getByRole("button", {
          name: "Ok",
        });
        await user.click(confirmButton);
      }

      await waitFor(() => {
        expect(axios[requestMethod]).toHaveBeenCalledWith(`${url}`, payload);
      });
    },
  );

  test("UserEventModal - advanced fields (killchain, malware family, related threat, external ref, tags and advanced evaluation)", async () => {
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

    const saveButton = screen.getByRole("button", { name: /Save/i });
    expect(saveButton).toBeInTheDocument();
    expect(saveButton.className).toContain("disabled");

    // add analyzable
    const analyzablesInput = screen.getAllByRole("textbox")[0];
    expect(analyzablesInput).toBeInTheDocument();
    expect(analyzablesInput.id).toBe("analyzables-0");
    expect(analyzablesInput.value).toBe("");
    fireEvent.change(analyzablesInput, { target: { value: "test.com" } });
    expect(analyzablesInput.value).toBe("test.com");

    // add manual evaluation
    const manualEvaluationTab = screen.getByText("Manual");
    expect(manualEvaluationTab).toBeInTheDocument();
    expect(manualEvaluationTab.closest("a").className).not.toContain("active");
    await user.click(manualEvaluationTab);
    const trusted = screen.getByRole("button", { name: "trusted" });
    expect(trusted).toBeInTheDocument();
    expect(trusted.className).not.toContain("active");
    await user.click(trusted);

    // change reliability
    const reliabilityInput = screen.getByRole("slider");
    expect(reliabilityInput).toBeInTheDocument();
    expect(reliabilityInput.value).toBe("10");
    fireEvent.change(reliabilityInput, { target: { value: "9" } });
    expect(screen.getByText("Reliability: 9")).toBeInTheDocument();

    // add reason
    const reasonInput = screen.getAllByRole("textbox")[1];
    expect(reasonInput).toBeInTheDocument();
    expect(reasonInput.id).toBe("reason");
    expect(reasonInput.value).toBe("");
    await user.type(reasonInput, "my reason");
    expect(reasonInput.value).toBe("my reason");

    // add malware family
    const malwareFamilyInput = screen.getAllByRole("textbox")[2];
    expect(malwareFamilyInput).toBeInTheDocument();
    expect(malwareFamilyInput.id).toBe("malware_family");
    expect(malwareFamilyInput.value).toBe("");
    fireEvent.change(malwareFamilyInput, { target: { value: "ursnif" } });
    expect(malwareFamilyInput.value).toBe("ursnif");

    // add related artifacts
    const relatedThreatsInput = screen.getAllByRole("textbox")[3];
    expect(relatedThreatsInput).toBeInTheDocument();
    expect(relatedThreatsInput.id).toBe("related_threats-0");
    expect(relatedThreatsInput.value).toBe("");
    fireEvent.change(relatedThreatsInput, {
      target: { value: "anotherArtifact.com" },
    });
    expect(relatedThreatsInput.value).toBe("anotherArtifact.com");

    // add external references
    const externalReferencesInput = screen.getAllByRole("textbox")[4];
    expect(externalReferencesInput).toBeInTheDocument();
    expect(externalReferencesInput.id).toBe("external_references-0");
    fireEvent.change(externalReferencesInput, {
      target: { value: "http://test.com" },
    });
    expect(externalReferencesInput.value).toBe("http://test.com");

    // add killchain phase
    const killChainPhaseInput = screen.getAllByRole("combobox")[0];
    expect(killChainPhaseInput).toBeInTheDocument();
    await userEvent.click(killChainPhaseInput);
    await userEvent.click(screen.getByText("action"));
    expect(screen.getByText("action")).toBeInTheDocument();
    expect(screen.queryByText("c2")).not.toBeInTheDocument(); // check other option are not visible

    // add tags (2 of them)
    expect(screen.getAllByText("Tags:")[0]).toBeInTheDocument();
    const tagsInput = screen.getAllByRole("combobox")[1];
    expect(tagsInput).toBeInTheDocument();
    await userEvent.click(tagsInput);
    await userEvent.click(screen.getByText("phishing"));
    expect(screen.getByText("phishing")).toBeInTheDocument();
    expect(screen.queryByText("malware")).not.toBeInTheDocument(); // check other option are not visible
    await userEvent.click(tagsInput);
    await userEvent.click(screen.getByText("malware"));
    expect(screen.getByText("malware")).toBeInTheDocument();
    expect(screen.queryByText("scanner")).not.toBeInTheDocument(); // check other option are not visible

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
          reliability: "9",
          malware_family: "ursnif",
          related_threats: ["anotherArtifact.com"],
          external_references: ["http://test.com"],
          kill_chain_phase: "action",
          tags: ["phishing", "malware"],
        },
        reason: "my reason",
        decay_progression: "0",
        decay_timedelta_days: 120,
      });
    });
  });

  test("UserEventModal - advanced --> basic evaluation", async () => {
    const user = userEvent.setup();
    axios.get.mockImplementation(() =>
      Promise.resolve({ status: 200, data: { count: 0 } }),
    );
    render(
      <BrowserRouter>
        <UserEventModal toggle={() => jest.fn()} isOpen />
      </BrowserRouter>,
    );

    const basicEvaluationTab = screen.getByText("Basic");
    expect(basicEvaluationTab).toBeInTheDocument();
    expect(basicEvaluationTab.closest("a").className).toContain("active"); // selected
    const manualEvaluationTab = screen.getByText("Manual");
    expect(manualEvaluationTab).toBeInTheDocument();
    expect(manualEvaluationTab.closest("a").className).not.toContain("active"); // selected
    const malicious10 = screen.getByRole("button", {
      name: "Confirmed malicious",
    });
    expect(malicious10).toBeInTheDocument();
    expect(malicious10.className).toContain("active"); // selected
    const malicious7 = screen.getByRole("button", { name: "Malicious" });
    expect(malicious7).toBeInTheDocument();
    expect(malicious7.className).not.toContain("active");
    const trusted8 = screen.getByRole("button", { name: "Currently trusted" });
    expect(trusted8).toBeInTheDocument();
    expect(trusted8.className).not.toContain("active");
    const trusted10 = screen.getByRole("button", { name: "Trusted" });
    expect(trusted10).toBeInTheDocument();
    expect(trusted10.className).not.toContain("active");
    const reasonInput = screen.getAllByRole("textbox")[1];
    expect(reasonInput).toBeInTheDocument();
    expect(reasonInput.id).toBe("reason");
    expect(reasonInput.value).toBe("");

    await user.click(manualEvaluationTab);
    const malicious = screen.getByRole("button", { name: "malicious" });
    expect(malicious).toBeInTheDocument();
    expect(malicious.className).toContain("active");
    const trusted = screen.getByRole("button", { name: "trusted" });
    expect(trusted).toBeInTheDocument();
    expect(trusted.className).not.toContain("active");
    expect(screen.getByText("Reliability: 10")).toBeInTheDocument();

    const saveButton = screen.getByRole("button", { name: /Save/i });
    expect(saveButton).toBeInTheDocument();
    expect(saveButton.className).toContain("disabled");

    // set advanced evaluation
    await user.click(trusted);
    // change reliability
    const reliabilityInput = screen.getByRole("slider");
    expect(reliabilityInput).toBeInTheDocument();
    expect(reliabilityInput.value).toBe("10");
    fireEvent.change(reliabilityInput, { target: { value: "9" } });
    expect(screen.getByText("Reliability: 9")).toBeInTheDocument();
    // basic evaluation tab
    await user.click(basicEvaluationTab);
    const manualEvalWarning = screen.getByText(
      "Warning: Manual reliability has been set and save correctly. Selecting a new basic evaluation will overwrite the previous settings.",
    );
    expect(manualEvalWarning).toBeInTheDocument();
    // set manual evaluation
    await user.click(malicious7);
    expect(manualEvalWarning).not.toBeInTheDocument();
    expect(malicious7.className).toContain("active");
  });

  test("UserEventModal - exclude evaluation", async () => {
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

    const saveButton = screen.getByRole("button", { name: /Save/i });
    expect(saveButton).toBeInTheDocument();
    expect(saveButton.className).toContain("disabled");

    // add analyzable
    const analyzablesInput = screen.getAllByRole("textbox")[0];
    expect(analyzablesInput).toBeInTheDocument();
    expect(analyzablesInput.id).toBe("analyzables-0");
    expect(analyzablesInput.value).toBe("");
    fireEvent.change(analyzablesInput, { target: { value: "test.com" } });
    expect(analyzablesInput.value).toBe("test.com");

    // set exclude evaluation flag
    const excludeEvaluation = screen.getByRole("checkbox", {
      id: "exclude-evaluation-flag",
    });
    expect(excludeEvaluation).toBeInTheDocument();
    expect(excludeEvaluation).not.toBeChecked();
    await user.click(excludeEvaluation);

    const malicious10 = screen.getByRole("button", {
      name: "Confirmed malicious",
    });
    expect(malicious10).toBeInTheDocument();
    expect(malicious10.className).toContain("disabled");
    const malicious7 = screen.getByRole("button", { name: "Malicious" });
    expect(malicious7).toBeInTheDocument();
    expect(malicious7.className).toContain("disabled");
    const trusted8 = screen.getByRole("button", { name: "Currently trusted" });
    expect(trusted8).toBeInTheDocument();
    expect(trusted8.className).toContain("disabled");
    const trusted10 = screen.getByRole("button", { name: "Trusted" });
    expect(trusted10).toBeInTheDocument();
    expect(trusted10.className).toContain("disabled");

    // add reason
    const reasonInput = screen.getAllByRole("textbox")[1];
    expect(reasonInput).toBeInTheDocument();
    expect(reasonInput.id).toBe("reason");
    expect(reasonInput.value).toBe("");
    await user.type(reasonInput, "my reason");
    expect(reasonInput.value).toBe("my reason");

    // add malware family
    const malwareFamilyInput = screen.getAllByRole("textbox")[2];
    expect(malwareFamilyInput).toBeInTheDocument();
    expect(malwareFamilyInput.id).toBe("malware_family");
    expect(malwareFamilyInput.value).toBe("");
    fireEvent.change(malwareFamilyInput, { target: { value: "ursnif" } });
    expect(malwareFamilyInput.value).toBe("ursnif");

    // add related artifacts
    const relatedThreatsInput = screen.getAllByRole("textbox")[3];
    expect(relatedThreatsInput).toBeInTheDocument();
    expect(relatedThreatsInput.id).toBe("related_threats-0");
    expect(relatedThreatsInput.value).toBe("");
    fireEvent.change(relatedThreatsInput, {
      target: { value: "anotherArtifact.com" },
    });
    expect(relatedThreatsInput.value).toBe("anotherArtifact.com");

    // add external references
    const externalReferencesInput = screen.getAllByRole("textbox")[4];
    expect(externalReferencesInput).toBeInTheDocument();
    expect(externalReferencesInput.id).toBe("external_references-0");
    fireEvent.change(externalReferencesInput, {
      target: { value: "http://test.com" },
    });
    expect(externalReferencesInput.value).toBe("http://test.com");

    // add killchain phase
    const killChainPhaseInput = screen.getAllByRole("combobox")[0];
    expect(killChainPhaseInput).toBeInTheDocument();
    await userEvent.click(killChainPhaseInput);
    await userEvent.click(screen.getByText("action"));
    expect(screen.getByText("action")).toBeInTheDocument();
    expect(screen.queryByText("c2")).not.toBeInTheDocument(); // check other option are not visible

    // add tags (2 of them)
    expect(screen.getAllByText("Tags:")[0]).toBeInTheDocument();
    const tagsInput = screen.getAllByRole("combobox")[1];
    expect(tagsInput).toBeInTheDocument();
    await userEvent.click(tagsInput);
    await userEvent.click(screen.getByText("phishing"));
    expect(screen.getByText("phishing")).toBeInTheDocument();
    expect(screen.queryByText("malware")).not.toBeInTheDocument(); // check other option are not visible
    await userEvent.click(tagsInput);
    await userEvent.click(screen.getByText("malware"));
    expect(screen.getByText("malware")).toBeInTheDocument();
    expect(screen.queryByText("scanner")).not.toBeInTheDocument(); // check other option are not visible

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
          evaluation: null,
          reliability: "8",
          malware_family: "ursnif",
          related_threats: ["anotherArtifact.com"],
          external_references: ["http://test.com"],
          kill_chain_phase: "action",
          tags: ["phishing", "malware"],
        },
        reason: "my reason",
        decay_progression: "0",
        decay_timedelta_days: 120,
      });
    });
  });

  test("UserEventModal - onSubmitCallback is called after successful submission", async () => {
    const user = userEvent.setup();
    const onSubmitCallbackMock = jest.fn();
    axios.get.mockImplementation(() =>
      Promise.resolve({ status: 200, data: { count: 0 } }),
    );
    axios.post.mockImplementation(() =>
      Promise.resolve({ status: 200, data: {} }),
    );
    render(
      <BrowserRouter>
        <UserEventModal
          toggle={() => jest.fn()}
          isOpen
          onSubmitCallback={onSubmitCallbackMock}
        />
      </BrowserRouter>,
    );

    const analyzablesInput = screen.getAllByRole("textbox")[0];
    fireEvent.change(analyzablesInput, { target: { value: "test.com" } });
    const reasonInput = screen.getAllByRole("textbox")[1];
    fireEvent.change(reasonInput, { target: { value: "my reason" } });

    await screen.findByText("artifact");

    const saveButton = screen.getByRole("button", { name: /Save/i });
    expect(saveButton.className).not.toContain("disabled");

    await user.click(saveButton);
    await waitFor(() => {
      expect(onSubmitCallbackMock).toHaveBeenCalledWith(["test.com"]);
    });
  });
});
