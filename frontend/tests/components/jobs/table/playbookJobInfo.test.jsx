import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import { PlaybookInfoPopoverIcon } from "../../../../src/components/jobs/table/playbookJobInfo";

describe("test PlaybookInfoPopoverIcon", () => {
  test("playbook", async () => {
    const { container } = render(
      <BrowserRouter>
        <PlaybookInfoPopoverIcon
          job={{
            id: 108,
            user: {
              username: "test",
            },
            tags: [],
            analyzer_reports: [
              {
                id: 174,
                name: "Classic_DNS",
                process_time: 0.07,
                report: {
                  observable: "dns.google.com",
                  resolutions: [
                    {
                      TTL: 594,
                      data: "8.8.8.8",
                      name: "dns.google.com",
                      type: 1,
                    },
                    {
                      TTL: 594,
                      data: "8.8.4.4",
                      name: "dns.google.com",
                      type: 1,
                    },
                  ],
                },
                status: "SUCCESS",
                errors: [],
                start_time: "2023-05-31T08:19:03.380434Z",
                end_time: "2023-05-31T08:19:03.455218Z",
                runtime_configuration: {},
                type: "analyzer",
              },
            ],
            connector_reports: [],
            visualizer_reports: [],
            comments: [],
            permissions: {
              kill: true,
              delete: true,
              plugin_actions: true,
            },
            is_sample: false,
            md5: "f9bc35a57b22f82c94dbcc420f71b903",
            observable_name: "dns.google.com",
            observable_classification: "domain",
            file_name: "",
            file_mimetype: "",
            status: "reported_without_fails",
            runtime_configuration: {
              analyzers: {},
              connectors: {},
              visualizers: {},
            },
            received_request_time: "2023-05-31T08:19:03.256003",
            finished_analysis_time: "2023-05-31T08:19:04.484684",
            process_time: 0.23,
            tlp: "AMBER",
            errors: [],
            playbook_requested: "playbook_test",
            playbook_to_execute: "playbook_test",
            analyzers_requested: ["Classic_DNS"],
            connectors_requested: ["connector1", "connector2"],
            analyzers_to_execute: ["Classic_DNS"],
            connectors_to_execute: ["connector1", "connector2"],
            visualizers_to_execute: ["IP", "Dns"],
            pivots_to_execute: ["test_pivot"],
          }}
        />
      </BrowserRouter>,
    );

    const infoIcon = container.querySelector(`#jobtable-infoicon__job-108`);
    expect(infoIcon).toBeInTheDocument();
    // user hovers icon
    const user = userEvent.setup();
    await user.hover(infoIcon);

    await waitFor(() => {
      // card header
      const playbookInfoCardHeader = screen.getByText("playbook_test");
      expect(playbookInfoCardHeader).toBeInTheDocument();
      // card body
      expect(screen.getByText("1 analyzers")).toBeInTheDocument();
      expect(screen.getByText("2 connectors")).toBeInTheDocument();
      expect(screen.getByText("1 pivots")).toBeInTheDocument();
      expect(screen.getByText("2 visualizers")).toBeInTheDocument();
    });
  });

  test("custom analysis", async () => {
    const { container } = render(
      <BrowserRouter>
        <PlaybookInfoPopoverIcon
          job={{
            id: 108,
            user: {
              username: "test",
            },
            tags: [],
            analyzer_reports: [
              {
                id: 174,
                name: "Classic_DNS",
                process_time: 0.07,
                report: {
                  observable: "dns.google.com",
                  resolutions: [
                    {
                      TTL: 594,
                      data: "8.8.8.8",
                      name: "dns.google.com",
                      type: 1,
                    },
                    {
                      TTL: 594,
                      data: "8.8.4.4",
                      name: "dns.google.com",
                      type: 1,
                    },
                  ],
                },
                status: "SUCCESS",
                errors: [],
                start_time: "2023-05-31T08:19:03.380434Z",
                end_time: "2023-05-31T08:19:03.455218Z",
                runtime_configuration: {},
                type: "analyzer",
              },
            ],
            connector_reports: [],
            visualizer_reports: [],
            comments: [],
            permissions: {
              kill: true,
              delete: true,
              plugin_actions: true,
            },
            is_sample: false,
            md5: "f9bc35a57b22f82c94dbcc420f71b903",
            observable_name: "dns.google.com",
            observable_classification: "domain",
            file_name: "",
            file_mimetype: "",
            status: "reported_without_fails",
            runtime_configuration: {
              analyzers: {},
              connectors: {},
              visualizers: {},
            },
            received_request_time: "2023-05-31T08:19:03.256003",
            finished_analysis_time: "2023-05-31T08:19:04.484684",
            process_time: 0.23,
            tlp: "AMBER",
            errors: [],
            playbook_requested: "",
            playbook_to_execute: "",
            analyzers_requested: ["Classic_DNS"],
            connectors_requested: ["connector1", "connector2"],
            analyzers_to_execute: ["Classic_DNS"],
            connectors_to_execute: ["connector1", "connector2"],
            visualizers_to_execute: [],
            pivots_to_execute: ["test_pivot"],
          }}
        />
      </BrowserRouter>,
    );

    const infoIcon = container.querySelector(`#jobtable-infoicon__job-108`);
    expect(infoIcon).toBeInTheDocument();
    // user hovers icon
    const user = userEvent.setup();
    await user.hover(infoIcon);

    await waitFor(() => {
      // card header
      const playbookInfoCardHeader = screen.getByText("Custom analysis");
      expect(playbookInfoCardHeader).toBeInTheDocument();
      // card body
      expect(screen.getByText("1 analyzers")).toBeInTheDocument();
      expect(screen.getByText("2 connectors")).toBeInTheDocument();
      expect(screen.getByText("1 pivots")).toBeInTheDocument();
      expect(screen.getByText("0 visualizers")).toBeInTheDocument();
    });
  });
});
