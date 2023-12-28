import React, { useState, useEffect } from "react";
import { Container, Row, Col, ButtonGroup, Button } from "reactstrap";
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
import { useOrganizationStore } from "../../stores/useOrganizationStore";

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
  // const isSelectedUI = JobResultSections.VISUALIZER;
  const { guideState, setGuideState } = useGuideContext();

  const [orgstate, setorgState] = useState(() => false);
  // const [labelstate, setlabelState] = useState("Global");

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

  const { organization } = useOrganizationStore(
    React.useCallback(
      (state) => ({
        organization: state.organization,
      }),
      [],
    ),
  );

  return (
    <Container fluid id="Dashboard">
      {/* <div className="g-0 d-flex align-items-baseline flex-column flex-lg-row mb-2">
        <h3 className="fw-bold" id="Dashboard_title">
          Dashboard
        </h3>
        <ButtonGroup className="ms-2 mb-3 d-flex align-items-center">
          <Button
            outline={!state}
            color={state ? "primary" : "tertiary"}
            onClick={() => handleChange()}
          >
            GLOBAL
          </Button>
          <Button
            outline={state}
            color={!state ? "primary" : "tertiary"}
            onClick={() => handleChange()}
          >
              ORG
          </Button>
        </ButtonGroup>
        <ElasticTimePicker
          className="ms-auto"
          size="sm"
          defaultSelected={range}
          onChange={onTimeIntervalChange}
          id="Dashboard_timepicker"
        />

      </div> */}

      <div className="d-flex flex-wrap justify-content-between align-items-baseline mb-2">
        <div>
          <h3 className="fw-bold" id="Dashboard_title">
            Dashboard
          </h3>
        </div>
        <div className="d-flex flex-wrap align-items-baseline ">
          {organization?.name ? (
            <ButtonGroup className="mb-3">
              <Button
                outline={orgstate}
                color={!orgstate ? "primary" : "tertiary"}
                onClick={async () => {
                  if (orgstate) {
                    setorgState((prevState) => !prevState);
                  }
                }}
              >
                GLOBAL
              </Button>
              <Button
                outline={!orgstate}
                color={orgstate ? "primary" : "tertiary"}
                onClick={async () => {
                  if (!orgstate) {
                    setorgState((prevState) => !prevState);
                  }
                }}
              >
                ORG
              </Button>
            </ButtonGroup>
          ) : null}

          <ElasticTimePicker
            className="ms-2"
            size="sm"
            defaultSelected={range}
            onChange={onTimeIntervalChange}
            id="Dashboard_timepicker"
          />
        </div>
      </div>

      <Row className="d-flex flex-wrap flex-lg-nowrap">
        {charts1.map(([id, header, Component], index) => (
          <Col key={id} md={12} lg={index === 0 ? 6 : 3}>
            <SmallInfoCard
              id={id}
              header={header}
              body={
                <div className="pt-2">
                  <Component
                    sendProp={{
                      key: orgstate,
                    }}
                  />
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
                  <Component
                    sendProp={{
                      key: orgstate,
                    }}
                  />
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
