import React from "react";
import { Container, Row, Col } from "reactstrap";
import useTitle from "react-use/lib/useTitle";

import {
  ElasticTimePicker,
  SmallInfoCard,
  useTimePickerStore
} from "@certego/certego-ui";

import {
  JobStatusBarChart,
  JobTypeBarChart,
  JobObsClassificationBarChart,
  JobFileMimetypeBarChart,
  JobObsNamePieChart,
  JobFileNamePieChart
} from "./utils/charts";

const charts1 = [
  ["JobStatusBarChart", "Job: Status", JobStatusBarChart],
  ["JobObsNamePieChart", "Job: Frequent Observable Names", JobObsNamePieChart],
  ["JobFileNamePieChart", "Job: Frequent File Names", JobFileNamePieChart],
];
const charts2 = [
  ["JobTypeBarChart", "Job: Type", JobTypeBarChart],
  [
    "JobObsClassificationBarChart",
    "Job: Observable Classification",
    JobObsClassificationBarChart,
  ],
  ["JobFileMimetypeBarChart", "Job: File Mimetype", JobFileMimetypeBarChart],
];

export default function Dashboard() {
  console.debug("Dashboard rendered!");

  const { range, onTimeIntervalChange, } = useTimePickerStore();

  // page title
  useTitle("IntelOwl | Dashboard", { restoreOnUnmount: true, });

  return (
    <Container fluid id="Dashboard">
      <Row
        noGutters
        className="d-flex align-items-baseline flex-column flex-lg-row mb-2"
      >
        <h3 className="font-weight-bold">Dashboard</h3>
        <ElasticTimePicker
          className="ml-auto"
          size="sm"
          defaultSelected={range}
          onChange={onTimeIntervalChange}
        />
      </Row>
      <Row className="d-flex flex-wrap flex-lg-nowrap">
        {charts1.map(([id, header, Component], i) => (
          <Col key={id} md={12} lg={i === 0 ? 6 : 3}>
            <SmallInfoCard
              id={id}
              header={header}
              body={
                <div className="pt-2">
                  <Component />
                </div>
              }
              style={{ minHeight: 360, }}
            />
          </Col>
        ))}
      </Row>
      <Row className="d-flex flex-wrap flex-lg-nowrap mt-4">
        {charts2.map(([id, header, Component], i) => (
          <Col key={id} md={12} lg={4}>
            <SmallInfoCard
              id={id}
              header={header}
              body={
                <div className="pt-2">
                  <Component />
                </div>
              }
              style={{ minHeight: 360, }}
            />
          </Col>
        ))}
      </Row>
    </Container>
  );
}
