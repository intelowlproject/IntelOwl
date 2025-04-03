import React from "react";
import PropTypes from "prop-types";
import { Badge, UncontrolledTooltip } from "reactstrap";
import { FaTag } from "react-icons/fa";
import { VscFile } from "react-icons/vsc";
import { TbWorld } from "react-icons/tb";
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
      id={`evaluation__job${id}_${evaluation}`}
      className={`d-flex-center ${divClass}`}
    >
      {getIcon(icon)}
      <UncontrolledTooltip
        target={`evaluation__job${id}_${evaluation}`}
        placement="top"
        fade={false}
      >
        {evaluation.toUpperCase()}
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

export function ReliabilityBar(props) {
  const { id, reliability, evaluation, className } = props;
  const color = EvaluationColors?.[evaluation];

  return (
    <div
      id={`reliability-bar__job${id}_rel${reliability}`}
      className={`d-flex-center ${className}`}
      style={{ width: "300px" }}
    >
      {[1, 2, 3, 4, 5, 6, 7, 8, 9, 10].map((index) => (
        <hr
          style={{
            width: "10%",
            borderTop: "3px solid white",
            opacity: 1,
          }}
          className={`mt-1 me-1 ${
            index <= reliability ? `border-${color}` : "border-tertiary"
          }`}
        />
      ))}
      <UncontrolledTooltip
        target={`reliability-bar__job${id}_rel${reliability}`}
        placement="top"
        fade={false}
      >
        Reliability: {reliability}
      </UncontrolledTooltip>
    </div>
  );
}

ReliabilityBar.propTypes = {
  id: PropTypes.string.isRequired,
  reliability: PropTypes.string.isRequired,
  evaluation: PropTypes.number.isRequired,
  className: PropTypes.string,
};

ReliabilityBar.defaultProps = {
  className: null,
};

export function TagsBadge(props) {
  const { id, tag, className } = props;
  let color = "";
  let icon = "";
  if (Object.keys(TagsIcons).includes(tag)) {
    color = TagsColors?.[tag];
    icon = getIcon(TagsIcons?.[tag]);
  } else {
    color = "secondary";
    icon = <FaTag />;
  }

  const divClass = classnames(`bg-${color}`, className);

  return (
    <Badge id={`tag__${id}_${tag}`} className={`d-flex-center ${divClass}`}>
      {icon}
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

export function CountryBadge(props) {
  const { id, country, className } = props;

  return (
    <span
      id={`country__${id}_${country.toLowerCase()}`}
      className={`${className}`}
    >
      {getIcon(country)}
      <UncontrolledTooltip
        placement="top"
        target={`country__${id}_${country.toLowerCase()}`}
      >
        {country.toUpperCase()}
      </UncontrolledTooltip>
    </span>
  );
}

CountryBadge.propTypes = {
  id: PropTypes.string.isRequired,
  country: PropTypes.string.isRequired,
  className: PropTypes.string,
};

CountryBadge.defaultProps = {
  className: null,
};

export function MimetypeBadge(props) {
  const { id, mimetype, className } = props;

  return (
    <Badge
      id={`mimetype__job${id}`}
      className={`d-flex-center bg-secondary ${className}`}
    >
      <VscFile />
      <UncontrolledTooltip
        target={`mimetype__job${id}`}
        placement="top"
        fade={false}
      >
        {mimetype}
      </UncontrolledTooltip>
    </Badge>
  );
}

MimetypeBadge.propTypes = {
  id: PropTypes.string.isRequired,
  mimetype: PropTypes.string.isRequired,
  className: PropTypes.string,
};

MimetypeBadge.defaultProps = {
  className: null,
};

export function IspBadge(props) {
  const { id, isp, className } = props;

  return (
    <Badge
      id={`isp__${id}`}
      className={`d-flex-center bg-secondary ${className}`}
    >
      <TbWorld />
      <UncontrolledTooltip target={`isp__${id}`} placement="top" fade={false}>
        {isp}
      </UncontrolledTooltip>
    </Badge>
  );
}

IspBadge.propTypes = {
  id: PropTypes.string.isRequired,
  isp: PropTypes.string.isRequired,
  className: PropTypes.string,
};

IspBadge.defaultProps = {
  className: null,
};
