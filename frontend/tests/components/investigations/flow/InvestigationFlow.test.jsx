/* eslint-disable id-length */
import React from "react";
import "@testing-library/jest-dom";
import { render, screen, fireEvent } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import { InvestigationFlow } from "../../../../src/components/investigations/flow/InvestigationFlow";

jest.mock("reactflow/dist/style.css", () => {});

describe("test InvestigationFlow", () => {
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

  test("InvestigationFlow - only root", () => {
    const { container } = render(
      <BrowserRouter>
        <InvestigationFlow
          investigationTree={{
            name: "My test",
            owner: 2,
            jobs: [],
          }}
          investigationId={1}
          refetchTree={() => jest.fn()}
          refetchInvestigation={() => jest.fn()}
        />
      </BrowserRouter>,
    );
    // Root node
    const rootNode = container.querySelector("#investigation-1");
    expect(rootNode).toBeInTheDocument();
    expect(rootNode.textContent).toBe("My test");

    expect(screen.getByText("Edges:")).toBeInTheDocument();
    expect(screen.getByText("job is concluded")).toBeInTheDocument();
    expect(screen.getByText("job is running")).toBeInTheDocument();
  });

  test("InvestigationFlow - root and 1 child", () => {
    const { container } = render(
      <BrowserRouter>
        <InvestigationFlow
          investigationTree={{
            name: "My test",
            owner: 2,
            jobs: [
              {
                pk: 10,
                analyzed_object_name: "test1.com",
                playbook: "Dns",
                status: "reported_without_fails",
                children: [],
              },
            ],
          }}
          investigationId={1}
          refetchTree={() => jest.fn()}
          refetchInvestigation={() => jest.fn()}
        />
      </BrowserRouter>,
    );
    // Root node
    const rootNode = container.querySelector("#investigation-1");
    expect(rootNode).toBeInTheDocument();
    expect(rootNode.textContent).toBe("My test");

    // Job node
    const jobNode = container.querySelector("#job-10");
    expect(jobNode).toBeInTheDocument();
    expect(jobNode.textContent).toBe("test1.com");
  });

  test("InvestigationFlow - root and 2 children", () => {
    const { container } = render(
      <BrowserRouter>
        <InvestigationFlow
          investigationTree={{
            name: "My test",
            owner: 2,
            jobs: [
              {
                pk: 10,
                analyzed_object_name: "test1.com",
                playbook: "Dns",
                status: "reported_without_fails",
                children: [],
              },
              {
                pk: 20,
                analyzed_object_name: "test2.com",
                playbook: "Dns",
                status: "reported_without_fails",
                children: [],
              },
            ],
          }}
          investigationId={1}
          refetchTree={() => jest.fn()}
          refetchInvestigation={() => jest.fn()}
        />
      </BrowserRouter>,
    );
    // Root node
    const rootNode = container.querySelector("#investigation-1");
    expect(rootNode).toBeInTheDocument();
    expect(rootNode.textContent).toBe("My test");

    // first job node
    const firstJobNode = container.querySelector("#job-10");
    expect(firstJobNode).toBeInTheDocument();
    expect(firstJobNode.textContent).toBe("test1.com");

    // second job node
    const secondJobNode = container.querySelector("#job-20");
    expect(secondJobNode).toBeInTheDocument();
    expect(secondJobNode.textContent).toBe("test2.com");
  });

  test("InvestigationFlow - root and 1 child + 1 pivot", () => {
    const { container } = render(
      <BrowserRouter>
        <InvestigationFlow
          investigationTree={{
            name: "My test",
            owner: 2,
            jobs: [
              {
                pk: 10,
                analyzed_object_name: "test1.com",
                playbook: "Dns",
                status: "reported_without_fails",
                children: [
                  {
                    pk: 11,
                    analyzed_object_name: "test11.com",
                    playbook: "Dns",
                    status: "reported_without_fails",
                    children: [],
                  },
                ],
              },
            ],
          }}
          investigationId={1}
          refetchTree={() => jest.fn()}
          refetchInvestigation={() => jest.fn()}
        />
      </BrowserRouter>,
    );
    // Root node
    const rootNode = container.querySelector("#investigation-1");
    expect(rootNode).toBeInTheDocument();
    expect(rootNode.textContent).toBe("My test");

    // first job node
    const firstJobNode = container.querySelector("#job-10");
    expect(firstJobNode).toBeInTheDocument();
    expect(firstJobNode.textContent).toBe("test1.com");

    // pivot node
    const secondJobNode = container.querySelector("#job-11");
    expect(secondJobNode).toBeInTheDocument();
    expect(secondJobNode.textContent).toBe("test11.com");
  });

  test("InvestigationFlow - root toolbar", () => {
    const { container } = render(
      <BrowserRouter>
        <InvestigationFlow
          investigationTree={{
            name: "My test",
            owner: 2,
            jobs: [],
          }}
          investigationId={1}
          refetchTree={() => jest.fn()}
          refetchInvestigation={() => jest.fn()}
          nodesDraggable={false}
        />
      </BrowserRouter>,
    );
    // Root node
    const rootNode = container.querySelector("#investigation-1");
    expect(rootNode).toBeInTheDocument();
    expect(rootNode.textContent).toBe("My test");

    fireEvent.click(rootNode);

    // root tollbar
    const rootTollbar = container.querySelector("#toolbar-investigation-1");
    expect(rootTollbar).toBeInTheDocument();
    const addJobButton = screen.getByRole("button", {
      name: "Add existing job",
    });
    expect(addJobButton).toBeInTheDocument();
    const createJobButton = screen.getByRole("link", { name: "Create Job" });
    expect(createJobButton).toBeInTheDocument();
    // link to scan page with investigation id in the param
    expect(createJobButton.href).toContain("/scan?investigation=1");
  });

  test("InvestigationFlow - job toolbar", () => {
    const { container } = render(
      <BrowserRouter>
        <InvestigationFlow
          investigationTree={{
            name: "My test",
            owner: 2,
            jobs: [
              {
                pk: 10,
                analyzed_object_name: "test1.com",
                playbook: "Dns",
                status: "reported_without_fails",
                received_request_time: "2024-04-03T13:08:45.417245Z",
                children: [
                  {
                    pk: 11,
                    analyzed_object_name: "test11.com",
                    playbook: "Dns",
                    status: "reported_without_fails",
                    children: [],
                    received_request_time: "2024-04-03T13:09:45.417245Z",
                  },
                ],
              },
            ],
          }}
          investigationId={1}
          refetchTree={() => jest.fn()}
          refetchInvestigation={() => jest.fn()}
          nodesDraggable={false}
        />
      </BrowserRouter>,
    );
    // Root node
    const rootNode = container.querySelector("#investigation-1");
    expect(rootNode).toBeInTheDocument();
    expect(rootNode.textContent).toBe("My test");

    // first job node
    const firstJobNode = container.querySelector("#job-10");
    expect(firstJobNode).toBeInTheDocument();
    expect(firstJobNode.textContent).toBe("test1.com");

    // pivot node
    const secondJobNode = container.querySelector("#job-11");
    expect(secondJobNode).toBeInTheDocument();
    expect(secondJobNode.textContent).toBe("test11.com");

    fireEvent.click(firstJobNode);
    // first job tollbar
    const jobTollbar = container.querySelector("#toolbar-job-10");
    expect(jobTollbar).toBeInTheDocument();
    const removeJobButton = screen.getByRole("button", {
      name: "Remove Branch",
    });
    expect(removeJobButton).toBeInTheDocument();
    const linkFirstJobButton = screen.getByRole("link", { name: "Link" });
    expect(linkFirstJobButton).toBeInTheDocument();
    const firstJobPivotButton = screen.getByRole("link", { name: "Pivot" });
    expect(firstJobPivotButton).toBeInTheDocument();
    const firstJobCopyButton = screen.getByRole("button", { name: "Copy" });
    expect(firstJobCopyButton).toBeInTheDocument();
    // link to job page
    expect(linkFirstJobButton.href).toContain("/jobs/10/visualizer");
    // link pivot
    expect(firstJobPivotButton.href).toContain(
      "/scan?parent=10&observable=test1.com",
    );
    // job info
    const jobInfo = container.querySelector("#job10-info");
    expect(jobInfo).toBeInTheDocument();
    expect(jobInfo.textContent).toContain("Job:#10");
    expect(jobInfo.textContent).toContain("Name:test1.com");
    expect(jobInfo.textContent).toContain("Playbook:Dns");
    expect(jobInfo.textContent).toContain("Created:");

    fireEvent.click(secondJobNode);
    // pivot tollbar
    const secondJobTollbar = container.querySelector("#toolbar-job-11");
    expect(secondJobTollbar).toBeInTheDocument();
    const removeSecondJobButton = container.querySelector(
      "#investigation-removejobbtn",
    );
    expect(removeSecondJobButton).toBeNull(); // no remove button in pivot
    const linkSecondJobButton = screen.getByRole("link", { name: "Link" });
    expect(linkSecondJobButton).toBeInTheDocument();
    const secondJobPivotButton = screen.getByRole("link", { name: "Pivot" });
    expect(secondJobPivotButton).toBeInTheDocument();
    const secondJobCopyButton = screen.getByRole("button", { name: "Copy" });
    expect(secondJobCopyButton).toBeInTheDocument();
    // link to job page
    expect(linkSecondJobButton.href).toContain("/jobs/11/visualizer");
    // link pivot
    expect(secondJobPivotButton.href).toContain(
      "/scan?parent=11&observable=test11.com",
    );
    // job info
    const secondJobInfo = container.querySelector("#job11-info");
    expect(secondJobInfo).toBeInTheDocument();
    expect(secondJobInfo.textContent).toContain("Job:#11");
    expect(secondJobInfo.textContent).toContain("Name:test11.com");
    expect(secondJobInfo.textContent).toContain("Playbook:Dns");
    expect(jobInfo.textContent).toContain("Created:");
  });
});
