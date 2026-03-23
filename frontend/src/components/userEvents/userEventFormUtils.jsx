import React from "react";
import PropTypes from "prop-types";
import axios from "axios";
import { Col, Spinner, UncontrolledTooltip } from "reactstrap";
import { MdInfoOutline } from "react-icons/md";

import {
  UserEventTypes,
  evaluationOptions,
  basicEvaluationReliabilityOption,
  userEventTypesToApiMapping,
  basicEvaluationOptions,
} from "../../constants/userEventsConst";
import {
  DataModelKillChainPhasesDescriptions,
  DataModelEvaluations,
} from "../../constants/dataModelConst";
import { USER_EVENT_DOMAIN_WILDCARD } from "../../constants/apiURLs";
import {
  IP_REGEX,
  DOMAIN_REGEX,
  URL_REGEX,
  HASH_REGEX,
} from "../../constants/regexConst";

export function AnalyzableInputInfo(props) {
  const { data, isLoading } = props;

  const isWildcard =
    !isLoading &&
    (data?.type === UserEventTypes.IP_WILDCARD ||
      data?.type === UserEventTypes.DOMAIN_WILDCARD);

  return (
    <div className="row">
      <Col sm={4}>
        <small className="fst-italic">Type:</small>
        {isLoading ? (
          <Spinner type="border" size="sm" className="text-light ms-1" />
        ) : (
          <small className="text-info ms-2">
            {data?.type?.replace("_", " ")}
          </small>
        )}
      </Col>
      {isWildcard && (
        <Col sm={4} className="d-flex align-items-center ">
          <small className="fst-italic">Matches:</small>
          <div>
            <small className="text-info ms-2">
              {data?.matches?.length} analyzables
            </small>
            <MdInfoOutline
              id="matches-infoicon"
              fontSize="15"
              className="text-info ms-2"
            />
            <UncontrolledTooltip
              trigger="hover"
              delay={{ show: 0, hide: 200 }}
              target="matches-infoicon"
              placement="right"
              fade={false}
              innerClassName="p-2 text-start text-nowrap md-fit-content"
            >
              {data?.matches?.toString()}
            </UncontrolledTooltip>
          </div>
        </Col>
      )}
    </div>
  );
}

AnalyzableInputInfo.propTypes = {
  data: PropTypes.object,
  isLoading: PropTypes.bool.isRequired,
};

AnalyzableInputInfo.defaultProps = {
  data: undefined,
};

export function BasicEvaluationWarning(props) {
  const { evaluation, reliability, basicEvaluation } = props;

  return (
    <div className="d-flex flex-column" id="basic-evaluation-warning">
      {((evaluation.toString() === DataModelEvaluations.MALICIOUS &&
        ![
          basicEvaluationReliabilityOption.RELIABILITY_CONFIRMED_MALICIOUS,
          basicEvaluationReliabilityOption.RELIABILITY_MALICIOUS,
        ].includes(reliability)) ||
        (evaluation.toString() === DataModelEvaluations.TRUSTED &&
          ![
            basicEvaluationReliabilityOption.RELIABILITY_CURRENTLY_TRUSTED,
            basicEvaluationReliabilityOption.RELIABILITY_TRUSTED,
          ].includes(reliability))) && (
        <strong className="d-flex align-items-center mb-0 py-1 text-warning">
          Warning: Manual reliability has been set and save correctly. Selecting
          a new basic evaluation will overwrite the previous settings.
        </strong>
      )}
      <small>{evaluationOptions[basicEvaluation]?.description}</small>
    </div>
  );
}

BasicEvaluationWarning.propTypes = {
  evaluation: PropTypes.string.isRequired,
  reliability: PropTypes.number.isRequired,
  basicEvaluation: PropTypes.string,
};

BasicEvaluationWarning.defaultProps = {
  basicEvaluation: undefined,
};

export const killChainPhaseOptionLabel = (killChainPhase) => (
  <div
    id={`killChainPhase__${killChainPhase}`}
    className="d-flex justify-content-start align-items-start flex-column"
  >
    <div className="d-flex justify-content-start align-items-baseline flex-column">
      <div>{killChainPhase}&nbsp;</div>
      <div className="small text-left text-muted">
        {DataModelKillChainPhasesDescriptions[killChainPhase.toUpperCase()] ||
          ""}
      </div>
    </div>
  </div>
);

export async function detectInputType(props) {
  const { value } = props;
  const data = {
    type: UserEventTypes.ANALYZABLE, // default type
    error: null,
  };
  // check ip wildcard
  if (IP_REGEX.test(value.split(/[/]/)[0]) && value.split(/[/]/).length === 2) {
    data.type = UserEventTypes.IP_WILDCARD;
    // validate ip wildcard
    await axios
      .put(`${userEventTypesToApiMapping.ip_wildcard}/validate`, {
        network: value,
      })
      .then(async (response) => {
        data.matches = response.data;
      })
      .catch((error) => {
        data.error = error?.response?.data?.errors?.detail;
        return data;
      });
  } else if (
    // check if the input is not a known observable
    !DOMAIN_REGEX.test(value) &&
    !IP_REGEX.test(value) &&
    !URL_REGEX.test(value) &&
    !HASH_REGEX.test(value) &&
    /\*/.test(value) // check if the character * is in the string
  ) {
    data.type = UserEventTypes.DOMAIN_WILDCARD;
    // check domain wildcard
    await axios
      .put(`${USER_EVENT_DOMAIN_WILDCARD}/validate`, { query: value })
      .then((response) => {
        data.matches = response.data;
      })
      .catch((error) => {
        data.error = error?.response?.data?.errors?.detail;
        return data;
      });
  }
  return data;
}

export function advancedToBasicEvaluation(props) {
  const { evaluation, reliability } = props;
  let basicEvaluation = null;
  if (
    evaluation === DataModelEvaluations.MALICIOUS &&
    reliability ===
      basicEvaluationReliabilityOption.RELIABILITY_CONFIRMED_MALICIOUS
  ) {
    basicEvaluation = basicEvaluationOptions.CONFIRMED_MALICIOUS;
  }
  if (
    evaluation === DataModelEvaluations.MALICIOUS &&
    reliability === basicEvaluationReliabilityOption.RELIABILITY_MALICIOUS
  ) {
    basicEvaluation = basicEvaluationOptions.MALICIOUS;
  }
  if (
    evaluation === DataModelEvaluations.TRUSTED &&
    reliability ===
      basicEvaluationReliabilityOption.RELIABILITY_CURRENTLY_TRUSTED
  ) {
    basicEvaluation = basicEvaluationOptions.CURRENTLY_TRUSTED;
  }
  if (
    evaluation === DataModelEvaluations.TRUSTED &&
    reliability === basicEvaluationReliabilityOption.RELIABILITY_TRUSTED
  ) {
    basicEvaluation = basicEvaluationOptions.TRUSTED;
  }
  return basicEvaluation;
}
