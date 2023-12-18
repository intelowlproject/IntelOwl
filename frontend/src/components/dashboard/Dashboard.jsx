import React, { useState, useEffect } from "react";
import { Container, Row, Col, FormGroup, Input, Label } from "reactstrap";
import useTitle from "react-use/lib/useTitle";
import {
  ElasticTimePicker,
  SmallInfoCard,
  useTimePickerStore,
} from "@certego/certego-ui";

import {
  JobStatusBarChart,
  JobTypeBarChart,
  JobObsClassificationBarChart,
  JobFileMimetypeBarChart,
  JobObsNamePieChart,
  JobFileHashPieChart,
} from "./utils/charts";

import { useGuideContext } from "../../contexts/GuideContext";

const charts1 = [
  ["JobStatusBarChart", "Job: Status", JobStatusBarChart],
  [
    "JobObsNamePieChart",
    "Job: Frequent IPs, Hash & Domains",
    JobObsNamePieChart,
  ],
  ["JobFileHashPieChart", "Job: Frequent Files", JobFileHashPieChart],
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
  const { guideState, setGuideState } = useGuideContext();

  const [state, setState] = useState(true);
  const [labelstate, setlabelState] = useState("Combined Reports");

  useEffect(() => {
    if (guideState.tourActive) {
      setTimeout(() => {
        setGuideState({ run: true, stepIndex: 8 });
      }, 100);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  console.debug("Dashboard rendered!");

  const { range, onTimeIntervalChange } = useTimePickerStore();

  // page title
  useTitle("IntelOwl | Dashboard", { restoreOnUnmount: true });

  async function handleChange() {
    console.debug("state is changed!");
    console.debug("this is working");
    setState(!state);
    if (state) {
      setlabelState("Own Org Reports");
    } else {
      setlabelState("Combined Reports");
    }
  }
  return (
    <Container fluid id="Dashboard">
      <div className="g-0 d-flex align-items-bottom flex-column flex-lg-row mb-2">
        <h3 className="fw-bold" id="Dashboard_title">
          Dashboard
        </h3>
        <ElasticTimePicker
          className="ms-auto"
          size="sm"
          defaultSelected={range}
          onChange={onTimeIntervalChange}
          id="Dashboard_timepicker"
        />
        <FormGroup switch className="d-flex align-items-center">
          <Input
            type="switch"
            role="switch"
            onClick={() => handleChange()}
            style={{ width: "3.5em", height: "2em" }}
            className="ms-auto"
          />
          <Label check style={{ fontSize: "1.3em" }} className="ms-3">
            {labelstate}
          </Label>
        </FormGroup>
      </div>
      <Row className="d-flex flex-wrap flex-lg-nowrap">
        {charts1.map(([id, header, Component], index) => (
          <Col key={id} md={12} lg={index === 0 ? 6 : 3}>
            <SmallInfoCard
              id={id}
              header={header}
              body={
                <div className="pt-2">
                  <Component />
                </div>
              }
              style={{ minHeight: 360 }}
            />
          </Col>
        ))}
      </Row>
      <Row className="d-flex flex-wrap flex-lg-nowrap mt-4">
        {charts2.map(([id, header, Component]) => (
          <Col key={id} md={12} lg={4}>
            <SmallInfoCard
              id={id}
              header={header}
              body={
                <div className="pt-2">
                  <Component />
                </div>
              }
              style={{ minHeight: 360 }}
            />
          </Col>
        ))}
      </Row>
    </Container>
  );
}
