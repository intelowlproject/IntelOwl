/* eslint-disable id-length */
import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import { PlaybookFlows } from "../../../../src/components/plugins/flows/PlaybookFlows";
import {
  mockedUsePluginConfigurationStore,
  mockedPlaybooks,
} from "../../../mock";

jest.mock("reactflow/dist/style.css", () => {});

jest.mock("../../../../src/stores/usePluginConfigurationStore", () => ({
  usePluginConfigurationStore: jest.fn((state) =>
    state(mockedUsePluginConfigurationStore),
  ),
}));

describe("test PlaybookFlows", () => {
  // mock needed for testing flow https://reactflow.dev/learn/advanced-use/testing#using-jest
  beforeEach(() => {
    let MockObserverInstance = typeof ResizeObserver;
    MockObserverInstance = {
      observe: jest.fn(),
      unobserve: jest.fn(),
      disconnect: jest.fn(),
    };
    global.ResizeObserver = jest
      .fn()
      .mockImplementation(() => MockObserverInstance);

    let MockDOMMatrixInstance = typeof DOMMatrixReadOnly;
    const mockDOMMatrix = (transform) => {
      const scale = transform?.match(/scale\(([1-9.])\)/)?.[1];
      MockDOMMatrixInstance = {
        m22: scale !== undefined ? +scale : 1,
      };
      return MockDOMMatrixInstance;
    };
    global.DOMMatrixReadOnly = jest
      .fn()
      .mockImplementation((transform) => mockDOMMatrix(transform));

    Object.defineProperties(global.HTMLElement.prototype, {
      offsetHeight: {
        get() {
          return parseFloat(this.style.height) || 1;
        },
      },
      offsetWidth: {
        get() {
          return parseFloat(this.style.width) || 1;
        },
      },
    });

    global.SVGElement.prototype.getBBox = () => ({
      x: 0,
      y: 0,
      width: 0,
      height: 0,
    });
  });

  test("PlaybookFlows - only root (playbook)", () => {
    const { container } = render(
      <BrowserRouter>
        <PlaybookFlows playbook={mockedPlaybooks.TEST_PLAYBOOK_FILE} />
      </BrowserRouter>,
    );
    // Root node
    const rootNode = container.querySelector("#playbook-5");
    expect(rootNode).toBeInTheDocument();
    expect(rootNode.textContent).toBe("TEST_PLAYBOOK_FILE");
    const playbookBadge = screen.getByText("Playbook");
    expect(playbookBadge).toBeInTheDocument();
    expect(playbookBadge.className).toContain("badge bg-secondary");
  });

  test("PlaybookFlows - playbook + pivot + playbook", () => {
    const { container } = render(
      <BrowserRouter>
        <PlaybookFlows playbook={mockedPlaybooks.TEST_PLAYBOOK_DOMAIN} />
      </BrowserRouter>,
    );
    // Root node (playbook)
    const rootNode = container.querySelector("#playbook-2");
    expect(rootNode).toBeInTheDocument();
    expect(rootNode.textContent).toBe("TEST_PLAYBOOK_DOMAIN");
    const playbookBadge = screen.getAllByText("Playbook")[0];
    expect(playbookBadge).toBeInTheDocument();
    expect(playbookBadge.className).toContain("badge bg-secondary");
    // pivot node
    const pivotNode = container.querySelector("#pivot-13");
    expect(pivotNode).toBeInTheDocument();
    expect(pivotNode.textContent).toBe("TEST_PIVOT");
    const pivotBadge = screen.getByText("Pivot");
    expect(pivotBadge).toBeInTheDocument();
    expect(pivotBadge.className).toContain("bg-advisory badge");
    // second playbook
    const secondPlaybookNode = container.querySelector("#playbook-1");
    expect(secondPlaybookNode).toBeInTheDocument();
    expect(secondPlaybookNode.textContent).toBe("TEST_PLAYBOOK_IP");
    const secondPlaybookBadge = screen.getAllByText("Playbook")[1];
    expect(secondPlaybookBadge).toBeInTheDocument();
    expect(secondPlaybookBadge.className).toContain("badge bg-secondary");
  });

  test("PlaybookFlows - playbook + pivot + playbook not configured", () => {
    mockedUsePluginConfigurationStore.pivots.push({
      id: 3,
      name: "TEST_PIVOT_ERROR",
      description: "pivot: test",
      python_module: "self_analyzable.SelfAnalyzable",
      playbooks_choice: ["NO_CONFIGURED_PLAYBOOK"],
      disabled: false,
      soft_time_limit: 60,
      routing_key: "default",
      health_check_status: true,
      delay: "00:00:00",
      health_check_task: null,
      config: {
        queue: "default",
        soft_time_limit: 60,
      },
      related_analyzer_configs: ["TEST_ANALYZER"],
      secrets: {},
      params: {},
      verification: {
        configured: true,
        details: "Ready to use!",
        missing_secrets: [],
      },
    });
    mockedPlaybooks.TEST_PLAYBOOK_DOMAIN.pivots = ["TEST_PIVOT_ERROR"];

    const { container } = render(
      <BrowserRouter>
        <PlaybookFlows playbook={mockedPlaybooks.TEST_PLAYBOOK_DOMAIN} />
      </BrowserRouter>,
    );
    // Root node (playbook)
    const rootNode = container.querySelector("#playbook-2");
    expect(rootNode).toBeInTheDocument();
    expect(rootNode.textContent).toBe("TEST_PLAYBOOK_DOMAIN");
    const playbookBadge = screen.getAllByText("Playbook")[0];
    expect(playbookBadge).toBeInTheDocument();
    expect(playbookBadge.className).toContain("badge bg-secondary");
    // pivot node
    const pivotNode = container.querySelector("#pivot-3");
    expect(pivotNode).toBeInTheDocument();
    expect(pivotNode.textContent).toBe("TEST_PIVOT_ERROR");
    const pivotBadge = screen.getByText("Pivot");
    expect(pivotBadge).toBeInTheDocument();
    expect(pivotBadge.className).toContain("bg-advisory badge");
    const pivotWarningIcon = container.querySelector("#pivot-warning-icon");
    expect(pivotWarningIcon).toBeInTheDocument();
    // second playbook
    const secondPlaybookNode = container.querySelector(
      "#playbook-NO_CONFIGURED_PLAYBOOK",
    );
    expect(secondPlaybookNode).toBeInTheDocument();
    expect(secondPlaybookNode.textContent).toBe("NO_CONFIGURED_PLAYBOOK");
    const secondPlaybookBadge = screen.getAllByText("Playbook")[1];
    expect(secondPlaybookBadge).toBeInTheDocument();
    expect(secondPlaybookBadge.className).toContain("badge bg-secondary");
    expect(secondPlaybookBadge).toHaveStyle(`opacity: 0.5`);
  });
});
