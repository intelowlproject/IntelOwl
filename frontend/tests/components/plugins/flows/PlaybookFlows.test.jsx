/* eslint-disable id-length */
import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import {PlaybookFlows} from "../../../../src/components/plugins/flows/PlaybookFlows";
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
        <PlaybookFlows
          playbook={mockedPlaybooks.TEST_PLAYBOOK_FILE}
        />
      </BrowserRouter>,
    );
    // Root node
    const rootNode = container.querySelector("#playbook-5");
    expect(rootNode).toBeInTheDocument();
    expect(rootNode.textContent).toBe("TEST_PLAYBOOK_FILE");
    const playbookBadge = screen.getByText("Playbook");
    expect(playbookBadge).toBeInTheDocument();
    expect(playbookBadge.className).toContain("badge bg-#5593ab");
  });

  test("PlaybookFlows - playbook + pivot + playbook", () => {
    const { container } = render(
      <BrowserRouter>
        <PlaybookFlows
          playbook={mockedPlaybooks.TEST_PLAYBOOK_DOMAIN}
        />
      </BrowserRouter>,
    );
    // Root node (playbook)
    const rootNode = container.querySelector("#playbook-2");
    expect(rootNode).toBeInTheDocument();
    expect(rootNode.textContent).toBe("TEST_PLAYBOOK_DOMAIN");
    const playbookBadge = screen.getAllByText("Playbook")[0];
    expect(playbookBadge).toBeInTheDocument();
    expect(playbookBadge.className).toContain("badge bg-#5593ab");
    // pivot node
    const pivotNode = container.querySelector("#pivot-13");
    expect(pivotNode).toBeInTheDocument();
    expect(pivotNode.textContent).toBe("TEST_PIVOT");
    const pivotBadge = screen.getByText("Pivot");
    expect(pivotBadge).toBeInTheDocument();
    expect(pivotBadge.className).toContain("badge bg-#b5ba66");
    // second playbook
    const secondPlaybookNode = container.querySelector("#playbook-1");
    expect(secondPlaybookNode).toBeInTheDocument();
    expect(secondPlaybookNode.textContent).toBe("TEST_PLAYBOOK_IP");
    const secondPlaybookBadge = screen.getAllByText("Playbook")[1];
    expect(secondPlaybookBadge).toBeInTheDocument();
    expect(secondPlaybookBadge.className).toContain("badge bg-#5593ab");
  });
});
