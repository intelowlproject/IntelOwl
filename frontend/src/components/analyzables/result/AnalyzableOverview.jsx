import React from "react";
import PropTypes from "prop-types";
import useAxios from "axios-hooks";
import { Col, Row, Container } from "reactstrap";
import { FaTag } from "react-icons/fa";

import { DateHoverable, DataTable, Loader } from "@certego/certego-ui";

import { AnalyzableActionsBar } from "./AnalyzableActionBar";
import { AnalyzableInfoCard } from "./AnalyzableInfoCard";
import { analyzablesHistoryTableColumns } from "./analyzablesHistoryTableColumns";

import { HorizontalListVisualizer } from "../../common/visualizer/elements/horizontalList";
import { TitleVisualizer } from "../../common/visualizer/elements/title";
import { BaseVisualizer } from "../../common/visualizer/elements/base";
import { VerticalListVisualizer } from "../../common/visualizer/elements/verticalList";
import { BooleanVisualizer } from "../../common/visualizer/elements/bool";

import { LastEvaluationComponent } from "../../common/engineBadges";
import { DataModelTagsIcons } from "../../../constants/dataModelConst";
import { TagsColors } from "../../../constants/colorConst";
import { getIcon } from "../../common/icon/icons";
import { AnalyzableHistoryTypes } from "../../../constants/miscConst";
import { ANALYZABLES_URI } from "../../../constants/apiURLs";

const tableInitialState = {
  pageSize: 10,
  sortBy: [{ id: "date", desc: true }],
};

export function AnalyzableOverview({ analyzable }) {
  console.debug("AnalyzableOverview rendered");

  // API to download the analyzable history data
  const [{ data: history, loading, error }] = useAxios(
    {
      url: `${ANALYZABLES_URI}/${analyzable.id}/history`,
    },
    { cache: false },
  );

  const jobs = history?.jobs?.map((job) => ({
    ...job,
    type: AnalyzableHistoryTypes.JOB,
  }));
  const userEvents = history?.user_events?.map((userEvent) => ({
    ...userEvent,
    type: AnalyzableHistoryTypes.USER_EVENT,
  }));
  const userDomainWildCardEvents = history?.user_domain_wildcard_events?.map(
    (userEvent) => ({
      ...userEvent,
      type: AnalyzableHistoryTypes.USER_DOMAIN_WILDCARD_EVENT,
    }),
  );
  const userIpWildCardEvents = history?.user_ip_wildcard_events?.map(
    (userEvent) => ({
      ...userEvent,
      type: AnalyzableHistoryTypes.USER_IP_WILDCARD_EVENT,
    }),
  );

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
              Artifact #{analyzable.id}
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
            alignment="around"
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
                analyzable.last_data_model.evaluation && (
                  <div
                    className="d-flex justify-content-center"
                    style={{ width: "200px" }}
                  >
                    <LastEvaluationComponent
                      id={analyzable.id}
                      reliability={analyzable.last_data_model.reliability}
                      evaluation={analyzable.last_data_model.evaluation}
                    />
                  </div>
                ),
              ],
              [
                "Last Evaluation Date",
                <DateHoverable
                  ago
                  noHover
                  value={analyzable.last_data_model.date}
                  format="hh:mm:ss a MMM do, yyyy"
                />,
              ],
              ["Malware Family", analyzable.last_data_model.malware_family],
              ["Killchain Phase", analyzable.last_data_model.kill_chain_phase],
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
                (analyzable.last_data_model.tags || []).map((tag, index) => (
                  <BooleanVisualizer
                    value={tag}
                    id={`tags-${index}`}
                    icon={
                      Object.keys(DataModelTagsIcons).includes(tag) ? (
                        getIcon(DataModelTagsIcons?.[tag])
                      ) : (
                        <FaTag />
                      )
                    }
                    activeColor={
                      Object.keys(DataModelTagsIcons).includes(tag)
                        ? TagsColors?.[tag]
                        : "secondary"
                    }
                    size="h6"
                  />
                )),
              ],
              [
                "External References",
                analyzable.last_data_model.external_references.map(
                  (value, index) => (
                    <BaseVisualizer
                      value={value}
                      id={`external_references-${index}`}
                      size="h6"
                    />
                  ),
                ),
              ],
              [
                "Reasons",
                analyzable.last_data_model.related_threats.map(
                  (value, index) => (
                    <BaseVisualizer
                      value={value}
                      id={`related_threats-${index}`}
                      size="h6"
                    />
                  ),
                ),
              ],
            ].map(([title, values], index) => (
              <VerticalListVisualizer
                id={`vlist-visualizer__element-${index}`}
                alignment="center"
                startOpen={values.length <= 5}
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
        <Loader
          loading={loading}
          error={error}
          render={() => (
            <DataTable
              data={jobs.concat(
                userEvents,
                userDomainWildCardEvents,
                userIpWildCardEvents,
              )}
              config={{}}
              initialState={tableInitialState}
              columns={analyzablesHistoryTableColumns}
              autoResetPage
            />
          )}
        />
      </Row>
    </Container>
  );
}

AnalyzableOverview.propTypes = {
  analyzable: PropTypes.object.isRequired,
};
