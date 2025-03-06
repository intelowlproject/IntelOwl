import React from "react";
import PropTypes from "prop-types";
import { Badge, UncontrolledTooltip } from "reactstrap";
import classnames from "classnames";
import { EvaluationColors, TagsColors } from "../../constants/colorConst";
import { EvaluationIcons, TagsIcons } from "../../constants/engineConst";
import { getIcon } from "./icon/icons";

export function EvaluationBadge(props) {
  const { id, evaluation, className } = props;

  const color = EvaluationColors?.[evaluation];
  const divClass = classnames(`bg-${color}`, className);
  const icon = EvaluationIcons?.[evaluation];

  return (
    <Badge
      id={`evaluation__${id}_${evaluation}`}
      className={`d-flex-center ${divClass}`}
    >
      {getIcon(icon)}
      <UncontrolledTooltip
        target={`evaluation__${id}_${evaluation}`}
        placement="top"
        fade={false}
      >
        Evaluation: {evaluation}
      </UncontrolledTooltip>
    </Badge>
  );
}

EvaluationBadge.propTypes = {
  id: PropTypes.string.isRequired,
  evaluation: PropTypes.string.isRequired,
  className: PropTypes.string,
};

EvaluationBadge.defaultProps = {
  className: null,
};

export function ReliabilityBadge(props) {
  const { id, reliability, className } = props;

  return (
    <Badge
      id={`reliability__${id}`}
      className={`d-flex-center bg-info ${className}`}
    >
      {reliability}
      <UncontrolledTooltip
        target={`reliability__${id}`}
        placement="top"
        fade={false}
      >
        Reliability: {reliability}
      </UncontrolledTooltip>
    </Badge>
  );
}

ReliabilityBadge.propTypes = {
  id: PropTypes.string.isRequired,
  reliability: PropTypes.string.isRequired,
  className: PropTypes.string,
};

ReliabilityBadge.defaultProps = {
  className: null,
};

export function TagsBadge(props) {
  const { id, tag, className } = props;
  let color = "";
  let icon = "";
  if (Object.keys(TagsIcons).includes(tag)) {
    color = TagsColors?.[tag];
    icon = TagsIcons?.[tag];
  } else {
    color = "secondary";
    icon = "tag";
  }

  const divClass = classnames(`bg-${color}`, className);

  return (
    <Badge id={`tag__${id}_${tag}`} className={`d-flex-center ${divClass}`}>
      {getIcon(icon)}
      <UncontrolledTooltip
        target={`tag__${id}_${tag}`}
        placement="top"
        fade={false}
      >
        {tag}
      </UncontrolledTooltip>
    </Badge>
  );
}

TagsBadge.propTypes = {
  id: PropTypes.string.isRequired,
  tag: PropTypes.string.isRequired,
  className: PropTypes.string,
};

TagsBadge.defaultProps = {
  className: null,
};
