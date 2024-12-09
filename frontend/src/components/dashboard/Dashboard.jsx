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
  JobTopPlaybookBarChart,
  JobTopUserBarChart,
  JobTopTLPBarChart,
} from "./charts";

import { useGuideContext } from "../../contexts/GuideContext";
import { useOrganizationStore } from "../../stores/useOrganizationStore";

const typeRow = [
  ["JobTypeBarChart", "Job: Type", JobTypeBarChart],
  [
    "JobObsClassificationBarChart",
    "Job: Observable Classification",
    JobObsClassificationBarChart,
  ],
  ["JobFileMimetypeBarChart", "Job: File Mimetype", JobFileMimetypeBarChart],
];
const usageRow = [
  ["JobTopPlaybookBarChart", "Job: Top 5 Playbooks", JobTopPlaybookBarChart],
  ["JobTopUserBarChart", "Job: Top 5 Users", JobTopUserBarChart],
  ["JobTopTLPBarChart", "Job: Top 5 TLP", JobTopTLPBarChart],
];

export default function Dashboard() {
  const { guideState, setGuideState } = useGuideContext();

  const [orgState, setOrgState] = useState(() => false);

  useEffect(() => {
    if (guideState.tourActive) {
      setTimeout(() => {
        setGuideState({ run: true, stepIndex: 9 });
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
                outline={orgState}
                color={orgState ? "tertiary" : "primary"}
                onClick={async () => {
                  if (orgState) {
                    setOrgState((prevState) => !prevState);
                  }
                }}
              >
                GLOBAL
              </Button>
              <Button
                outline={!orgState}
                color={orgState ? "primary" : "tertiary"}
                onClick={async () => {
                  if (!orgState) {
                    setOrgState((prevState) => !prevState);
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
        <Col key="JobStatusBarChart" md={12}>
          <SmallInfoCard
            id="JobStatusBarChart"
            header="Job: Status"
            body={
              <div className="pt-2">
                <JobStatusBarChart orgName={orgState} />
              </div>
            }
            style={{ minHeight: 360 }}
          />
        </Col>
      </Row>
      <Row className="d-flex flex-wrap flex-lg-nowrap mt-4">
        {typeRow.map(([id, header, Component]) => (
          <Col key={id} md={12} lg={4}>
            <SmallInfoCard
              id={id}
              header={header}
              body={
                <div className="pt-2">
                  <Component orgName={orgState} />
                </div>
              }
              style={{ minHeight: 360 }}
            />
          </Col>
        ))}
      </Row>
      <Row className="d-flex flex-wrap flex-lg-nowrap mt-4">
        {usageRow.map(([id, header, Component]) => (
          <Col key={id} md={12} lg={4}>
            <SmallInfoCard
              id={id}
              header={header}
              body={
                <div className="pt-2">
                  <Component orgName={orgState} />
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
