import React from "react";
import {
  Card,
  CardHeader,
  CardBody,
  ListGroup,
  Collapse,
  Button,
  Badge,
} from "reactstrap";
import { BsBoxArrowLeft } from "react-icons/bs";
import PropTypes from "prop-types";
import axios from "axios";
import {
  Loader,
  DateHoverable,
  ArrowToggleIcon,
  ContentSection,
} from "@certego/certego-ui";

import {
  UserEventTypes,
  userEventTypesToApiMapping,
} from "../../constants/userEventsConst";
import { useAuthStore } from "../../stores/useAuthStore";
import { LastEvaluationComponent, TagsBadge } from "../common/engineBadges";
import {
  advancedToBasicEvaluation,
  killChainPhaseOptionLabel,
} from "./userEventFormUtils";
import { TagsColors } from "../../constants/colorConst";

function UserExistingEvaluationsCard({
  analyzable,
  data,
  index,
  setUserExistingEvents,
  formik,
}) {
  console.debug("UserExistingEvaluationsCard rendered!");
  // store
  const [user] = useAuthStore((state) => [state.user]);
  // state
  const [loading, setLoading] = React.useState(true);
  const [existingEvent, setExistingEvent] = React.useState(null);
  const [isOpenCard, setIsOpenCard] = React.useState(false);

  /*
    analyzable =  google.com
    data = { type: artifact }
  */

  const fetchExistingEvaluations = async () => {
    let searchParams = `analyzable_name=${analyzable}`; // default
    if (data?.type === UserEventTypes.IP_WILDCARD)
      searchParams = `network=${analyzable}`;
    if (data?.type === UserEventTypes.DOMAIN_WILDCARD)
      searchParams = `query=${analyzable}`;
    // check if an event already exists for the same user
    const responseEvent = await axios.get(
      `${userEventTypesToApiMapping[data?.type]}?username=${
        user.username
      }&${searchParams}`,
    );
    if (responseEvent.data.count === 1) {
      const event = responseEvent.data.results[0];
      setExistingEvent(event);
      setUserExistingEvents((prevState) => ({
        ...prevState,
        [analyzable]: { id: event?.analyzable?.id, event: event.id },
      }));
    }
    setLoading(false);
  };

  React.useEffect(() => {
    fetchExistingEvaluations();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [analyzable, data]);

  const fillForm = () => {
    const dataModel = existingEvent.data_model;
    const { evaluation } = dataModel;
    const { reliability } = dataModel;
    const basicEvaluation = advancedToBasicEvaluation({
      evaluation,
      reliability,
    });

    const values = {
      analyzables: formik.values.analyzables,
      basic_evaluation: basicEvaluation,
      evaluation,
      reliability,
      malware_family: dataModel.malware_family || "",
      related_threats:
        dataModel?.related_threats.length > 0
          ? dataModel.related_threats
          : [""],
      external_references:
        dataModel?.external_references.length > 0
          ? dataModel.external_references
          : [""],
      kill_chain_phase: dataModel?.kill_chain_phase
        ? {
            value: dataModel.kill_chain_phase,
            label: killChainPhaseOptionLabel(dataModel.kill_chain_phase),
          }
        : "",
      tags: dataModel?.tags
        ? dataModel.tags.map((tag) => ({
            value: tag,
            label: <Badge color={TagsColors[tag]}>{tag}</Badge>,
          }))
        : [],
      // fields not in the data model
      reason: existingEvent.reason || "",
      decay_progression: existingEvent.decay_progression,
      decay_timedelta_days: existingEvent.decay_timedelta_days,
    };
    formik.setValues({ ...values });
  };

  return (
    <Loader
      loading={loading}
      render={() => (
        <Card
          id={`UserExistingEvaluationsCard-${index}`}
          className="border-tertiary mb-2 pointer"
        >
          <CardHeader
            onClick={() => {
              if (existingEvent !== null) setIsOpenCard(!isOpenCard);
            }}
            className="d-flex justify-content-between align-items-center mx-3 bg-dark text-center p-0 py-1"
          >
            <span className="text-truncate" style={{ maxWidth: "75%" }}>
              {analyzable}
            </span>
            {existingEvent !== null && (
              <ArrowToggleIcon isExpanded={isOpenCard} />
            )}
          </CardHeader>
          <CardBody
            className="d-flex flex-column bg-darker p-2 px-4"
            style={{
              borderBottomLeftRadius: "0.75rem",
              borderBottomRightRadius: "0.75rem",
            }}
          >
            <div className="d-flex">
              <small className="text-light me-2 col-4">Date:</small>
              {existingEvent !== null ? (
                <DateHoverable
                  className="text-accent"
                  ago
                  value={existingEvent?.date}
                  format="hh:mm:ss a MMM do, yyyy"
                />
              ) : (
                <small className="text-gray">not found</small>
              )}
            </div>
            <Collapse
              isOpen={isOpenCard}
              id="UserExistingEvaluationsCard-collpse"
            >
              <hr className="mb-0 mt-2" />
              <ContentSection className="border-0 bg-darker px-0 py-1 mb-1">
                <ListGroup className="align-items-start">
                  {[
                    [
                      "Evaluation:",
                      existingEvent?.data_model?.evaluation && (
                        <LastEvaluationComponent
                          id={index}
                          reliability={existingEvent?.data_model.reliability}
                          evaluation={existingEvent?.data_model.evaluation}
                        />
                      ),
                    ],
                    ["Reason:", existingEvent?.reason || "-"],
                    [
                      "Malware family:",
                      existingEvent?.data_model.malware_family || "-",
                    ],
                    [
                      "Related artifacts:",
                      existingEvent?.data_model.related_threats || "-",
                    ],
                    [
                      "External references:",
                      existingEvent?.data_model.external_references || "-",
                    ],
                    [
                      "Kill chain phase:",
                      existingEvent?.data_model.kill_chain_phase || "-",
                    ],
                    [
                      "Tags:",
                      <div className="d-flex flex-wrap pt-1">
                        {existingEvent?.data_model.tags?.map(
                          (tag, indexTag) => (
                            <TagsBadge
                              id={`${data.id}_${indexTag}`}
                              tag={tag}
                              className="ms-1"
                            />
                          ),
                        )}
                      </div>,
                    ],
                  ].map(([key, value]) => (
                    <div
                      key={key}
                      className="ms-0 d-flex align-items-start w-100 pb-2"
                    >
                      <small className="fw-bold text-light me-2 col-4">
                        {key}
                      </small>
                      <small className="text-light col-8 pe-2">{value}</small>
                    </div>
                  ))}
                </ListGroup>
              </ContentSection>
              <Button
                size="xs"
                className="d-flex align-items-center"
                onClick={fillForm}
              >
                <BsBoxArrowLeft className="me-1" />
                <small>Fill with this</small>
              </Button>
            </Collapse>
          </CardBody>
        </Card>
      )}
    />
  );
}

UserExistingEvaluationsCard.propTypes = {
  data: PropTypes.object.isRequired,
  analyzable: PropTypes.string.isRequired,
  index: PropTypes.number.isRequired,
  setUserExistingEvents: PropTypes.func.isRequired,
  formik: PropTypes.object.isRequired,
};

export function UserExistingEvaluationsSection({
  inputData,
  analyzables,
  setUserExistingEvents,
  formik,
}) {
  console.debug("UserExistingEvaluationsSection rendered!");
  /*
    data = {
        google.com: { type: artifact, errors: {}, ... },
        1.2.3.4/24: { type: ip_wildcard, errors: {}, ... },
        *.google.com: { type: domain_wildcard, errors: {}, ... },
    }
  */
  return (
    <div className="p-3" id="user-events-existing-evaluations-section">
      <h6 className="mb-3 fw-bold">Your evaluations:</h6>
      {Object.entries(inputData)?.map(
        ([key, value], index) =>
          analyzables.includes(key) && (
            <UserExistingEvaluationsCard
              analyzable={key}
              data={value}
              index={index}
              setUserExistingEvents={setUserExistingEvents}
              formik={formik}
            />
          ),
      )}
    </div>
  );
}

UserExistingEvaluationsSection.propTypes = {
  inputData: PropTypes.object.isRequired,
  analyzables: PropTypes.array.isRequired,
  setUserExistingEvents: PropTypes.func.isRequired,
  formik: PropTypes.object.isRequired,
};
