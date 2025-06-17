import React from "react";
import PropTypes from "prop-types";
import { Col, Row, Container } from "reactstrap";
import { FaTag } from "react-icons/fa";

import { DateHoverable, DataTable } from "@certego/certego-ui";

import { AnalyzableActionsBar } from "./AnalyzableActionBar";
import { AnalyzableInfoCard } from "./AnalyzableInfoCard";
import { analyzablesHistoryTableColumns } from "./analyzablesHistoryTableColumns";

import { HorizontalListVisualizer } from "../../common/visualizer/elements/horizontalList";
import { TitleVisualizer } from "../../common/visualizer/elements/title";
import { BaseVisualizer } from "../../common/visualizer/elements/base";
import { VerticalListVisualizer } from "../../common/visualizer/elements/verticalList";
import { BooleanVisualizer } from "../../common/visualizer/elements/bool";

import { LastEvaluationComponent } from "../../common/engineBadges";
import { TagsIcons } from "../../../constants/engineConst";
import { TagsColors } from "../../../constants/colorConst";
import { getIcon } from "../../common/icon/icons";
import { AnalyzableHistoryTypes } from "../../../constants/miscConst";
import { UserReportDecay } from "../../userReports/UserReportDecay";

const tableInitialState = {
  pageSize: 10,
  sortBy: [{ id: "date", desc: true }],
};

export function AnalyzableOverview({ analyzable }) {
  console.debug("AnalyzableOverview rendered");

  const jobs = analyzable?.jobs?.map((job) => ({
    ...job,
    type: AnalyzableHistoryTypes.JOB,
  }));
  const userReports = analyzable?.user_events?.map((userEvent) => ({
    ...userEvent,
    type: AnalyzableHistoryTypes.USER_REPORT,
  }));
  const lastEvent = jobs
    .concat(userReports)
    .sort((elA, elB) => new Date(elB.date) - new Date(elA.date))[0];

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
                "Last Evaluation",
                lastEvent.data_model.evaluation && (
                  <div
                    className="d-flex justify-content-center"
                    style={{ width: "200px" }}
                  >
                    <LastEvaluationComponent
                      id={analyzable.id}
                      reliability={lastEvent.data_model.reliability}
                      evaluation={lastEvent.data_model.evaluation}
                    />
                  </div>
                ),
              ],
              [
                "Last Evaluation Date",
                <DateHoverable
                  ago
                  noHover
                  value={lastEvent.data_model.date}
                  format="hh:mm:ss a MMM do, yyyy"
                />,
              ],
              [
                "Decay",
                lastEvent.type === AnalyzableHistoryTypes.USER_REPORT ? (
                  <UserReportDecay
                    decay={lastEvent.next_decay}
                    reliability={lastEvent.data_model.reliability}
                  />
                ) : null,
              ],
              ["Malware Family", lastEvent.data_model.malware_family],
              ["Killchain Phase", lastEvent.data_model.kill_chain_phase],
            ].map(([title, value], index) => (
              <TitleVisualizer
                id={`title-visualizer__element-${index}`}
                title={
                  <BaseVisualizer
                    value={title}
                    id={`${title.replaceAll(" ", "_")}-title`}
                    bold
                    size="h5"
                    disable={!value}
                  />
                }
                value={
                  value && (
                    <BaseVisualizer
                      value={value}
                      id={`${title.replaceAll(" ", "_")}-value`}
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
              [
                "Tags",
                (lastEvent.data_model.tags || []).map((tag, index) => (
                  <BooleanVisualizer
                    value={tag}
                    id={`tags-${index}`}
                    icon={
                      Object.keys(TagsIcons).includes(tag) ? (
                        getIcon(TagsIcons?.[tag])
                      ) : (
                        <FaTag />
                      )
                    }
                    activeColor={
                      Object.keys(TagsIcons).includes(tag)
                        ? TagsColors?.[tag]
                        : "secondary"
                    }
                    size="h6"
                  />
                )),
              ],
              [
                "External References",
                lastEvent.data_model.external_references.map((value, index) => (
                  <BaseVisualizer
                    value={value}
                    id={`external_references-${index}`}
                    size="h6"
                  />
                )),
              ],
              [
                "Comments",
                lastEvent.data_model.related_threats.map((value, index) => (
                  <BaseVisualizer
                    value={value}
                    id={`related_threats-${index}`}
                    size="h6"
                  />
                )),
              ],
            ].map(([title, values], index) => (
              <VerticalListVisualizer
                id={`vlist-visualizer__element-${index}`}
                alignment="center"
                name={
                  <BaseVisualizer
                    value={`${title} (${values.length})`}
                    id={`${title.replace(" ", "_")}-title`}
                    bold
                    size="h6"
                  />
                }
                values={values}
                size="col-2"
                disable={values.length === 0}
                startOpen
              />
            ))}
          />
        </Col>
      </Row>
      <hr className="border-gray flex-grow-1 my-2" />
      {/* History table */}
      <Row className="g-0 mt-4">
        <Col>
          <h3 className="d-flex align-items-center mt-4">
            <span className="me-2 text-secondary">History</span>
          </h3>
        </Col>
      </Row>
      <Row className="mt-2">
        <DataTable
          data={jobs.concat(userReports)}
          config={{}}
          initialState={tableInitialState}
          columns={analyzablesHistoryTableColumns}
          autoResetPage
        />
      </Row>
    </Container>
  );
}

AnalyzableOverview.propTypes = {
  analyzable: PropTypes.object.isRequired,
};
