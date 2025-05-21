import React from "react";
import PropTypes from "prop-types";
import { Col, Row, Container } from "reactstrap";

import { DateHoverable } from "@certego/certego-ui";

import { AnalyzableActionsBar } from "./AnalyzableActionBar";
import { AnalyzableInfoCard } from "./AnalyzableInfoCard";

import { HorizontalListVisualizer } from "../common/visualizer/elements/horizontalList";
import { TitleVisualizer } from "../common/visualizer/elements/title";
import { BaseVisualizer } from "../common/visualizer/elements/base";
import { VerticalListVisualizer } from "../common/visualizer/elements/verticalList";

export function AnalyzableOverview({ analyzable }) {
  console.debug("AnalyzableOverview rendered");

  return (
    <Container fluid>
      {/* bar with analyzable id and utilities buttons */}
      <Row
        className="g-0 d-flex-between-end align-items-center"
        id="utilitiesRow"
      >
        <Col>
          <h2 className="d-flex align-items-center">
            <span className="me-2 text-secondary">
              Analyzable #{analyzable.id}
            </span>
          </h2>
        </Col>
        <Col md={8} className="d-flex justify-content-end mt-1">
          <AnalyzableActionsBar analyzable={analyzable} />
        </Col>
      </Row>
      {/* analyzable metadata card */}
      <Row className="g-0">
        <Col>
          <AnalyzableInfoCard analyzable={analyzable} />
        </Col>
      </Row>
      {/* analyzable visualizers */}
      <Row className="g-0 mt-4">
        <Col>
          <HorizontalListVisualizer
            id="analyzable-overview__first-row"
            alignment="center"
            values={[
              [
                "First Analysis",
                <DateHoverable
                  ago
                  noHover
                  value={analyzable.discovery_date}
                  format="hh:mm:ss a MMM do, yyyy"
                />,
              ],
              [
                "Last Analysis",
                <DateHoverable
                  ago
                  noHover
                  value={analyzable.discovery_date}
                  format="hh:mm:ss a MMM do, yyyy"
                />,
              ],
              ["Last Evaluation", analyzable.last_evaluation],
              [
                "Decay",
                <DateHoverable
                  ago
                  noHover
                  value={analyzable.discovery_date}
                  format="hh:mm:ss a MMM do, yyyy"
                />,
              ],
              ["Malware Family", analyzable.last_evaluation],
              ["Killchain phase", analyzable.killchain_phase],
            ].map(([title, value], index) => (
              <TitleVisualizer
                id={`title-visualizer__element-${index}`}
                title={
                  <BaseVisualizer
                    value={title}
                    id={`${title.replace(" ", "_")}-title`}
                    bold
                    size="h5"
                    disable={!value}
                  />
                }
                value={
                  value && (
                    <BaseVisualizer
                      value={value}
                      id={`${title.replace(" ", "_")}-value`}
                      size="h6"
                    />
                  )
                }
                size="col-2"
              />
            ))}
          />
        </Col>
      </Row>
      <hr className="border-gray flex-grow-1 my-2" />
      <Row className="g-0 mt-2">
        <Col>
          <HorizontalListVisualizer
            id="analyzable-overview__second-row"
            alignment="around"
            values={[
              // ["Tags", analyzable.tags],
              // ["External references", analyzable.external_references],
              // ["comments", analyzable.related_threat],
              ["Tags", []],
              ["External references", []],
              ["comments", []],
            ].map(([title, value], index) => (
              <VerticalListVisualizer
                id={`vlist-visualizer__element-${index}`}
                alignment="center"
                name={
                  <BaseVisualizer
                    value={title}
                    id={`${title.replace(" ", "_")}-title`}
                    bold
                  />
                }
                values={value}
                size="col-2"
                disable={value.length === 0}
                startOpen
              />
            ))}
          />
        </Col>
      </Row>
      <hr className="border-gray flex-grow-1 my-2" />
    </Container>
  );
}

AnalyzableOverview.propTypes = {
  analyzable: PropTypes.object.isRequired,
};
