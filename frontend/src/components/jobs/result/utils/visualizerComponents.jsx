import React, { Fragment, useState } from "react";
import PropTypes from "prop-types";
import {
  Badge,
  Button,
  Card,
  CardTitle,
  Collapse,
  ListGroup,
  ListGroupItem,
} from "reactstrap";
import { BiUpArrow, BiDownArrow } from "react-icons/bi";

function BaseVisualizer({ value, color, link, className, additionalElement }) {
  const unlinkedTitle = (
    <p color={color} className={className}>
      {value}
      {additionalElement}
    </p>
  );
  if (link) {
    return <a href={link}>{unlinkedTitle}</a>;
  }
  return unlinkedTitle;
}

BaseVisualizer.propTypes = {
  value: PropTypes.string.isRequired,
  color: PropTypes.string,
  link: PropTypes.string,
  className: PropTypes.string,
  additionalElement: PropTypes.element,
};

BaseVisualizer.defaultProps = {
  color: "",
  link: "",
  className: "",
  additionalElement: null,
};

function StringVisualizerField({
  fieldName,
  fieldValue,
  titleColor,
  titleLink,
  titleClassName,
  titleAdditionalElement,
  valueColor,
  valueLink,
  valueClassName,
  valueAdditionalElement,
}) {
  return (
    <div className="d-flex flex-column align-items-center">
      <BaseVisualizer
        value={fieldName}
        color={titleColor}
        link={titleLink}
        className={`small fw-bold text-light ${titleClassName}`}
        additionalElement={titleAdditionalElement}
      />
      <div className="bg-dark p-1 text-light d-inline-flex">
        <BaseVisualizer
          value={fieldValue}
          color={valueColor}
          link={valueLink}
          className={valueClassName}
          additionalElement={valueAdditionalElement}
        />
      </div>
    </div>
  );
}

StringVisualizerField.propTypes = {
  fieldName: PropTypes.string.isRequired,
  fieldValue: PropTypes.string.isRequired,
  titleColor: PropTypes.string,
  titleLink: PropTypes.string,
  titleClassName: PropTypes.string,
  titleAdditionalElement: PropTypes.element,
  valueColor: PropTypes.string,
  valueLink: PropTypes.string,
  valueClassName: PropTypes.string,
  valueAdditionalElement: PropTypes.element,
};

StringVisualizerField.defaultProps = {
  titleColor: "",
  titleLink: "",
  titleClassName: "",
  titleAdditionalElement: null,
  valueColor: "",
  valueLink: "",
  valueClassName: "",
  valueAdditionalElement: null,
};

function BooleanVisualizerField({
  fieldName,
  fieldValue,
  pill,
  className,
  activeColor,
  additionalElement,
}) {
  return (
    <Badge
      pill={pill}
      color={fieldValue === true ? activeColor : "gray"}
      className={className}
    >
      {fieldName}
      {additionalElement}
    </Badge>
  );
}

BooleanVisualizerField.propTypes = {
  fieldName: PropTypes.string.isRequired,
  fieldValue: PropTypes.bool.isRequired,
  pill: PropTypes.bool,
  className: PropTypes.string,
  activeColor: PropTypes.bool,
  additionalElement: PropTypes.element,
};

BooleanVisualizerField.defaultProps = {
  pill: true,
  className: "",
  activeColor: "danger",
  additionalElement: null,
};

function ListVisualizerField({
  fieldName,
  fieldValue,
  titleColor,
  titleLink,
  titleClassName,
  titleAdditionalElement,
}) {
  const [isListOpen, setIsListOpen] = useState(false);
  const toggleList = () => setIsListOpen(!isListOpen);

  return (
    <Card>
      <CardTitle className="p-1 mb-0">
        <Button className="p-0 w-100" onClick={toggleList}>
          <BaseVisualizer
            value={fieldName}
            color={titleColor}
            link={titleLink}
            className={titleClassName}
            additionalElement={
              <Fragment>
                {isListOpen ? (
                  <BiUpArrow className="mx-1" />
                ) : (
                  <BiDownArrow className="mx-1" />
                )}
                {titleAdditionalElement}
              </Fragment>
            }
          />
        </Button>
      </CardTitle>
      <Collapse isOpen={isListOpen}>
        <ListGroup flush>
          {fieldValue.map((listElement) => (
            <ListGroupItem key={listElement.value} className="text-light">
              <BaseVisualizer
                value={listElement.value}
                color={listElement.valueColor}
                link={listElement.valueLink}
                className={`mb-0 ${listElement.valueClassName}`}
                additionalElement={listElement.valueAdditionalElement}
              />
            </ListGroupItem>
          ))}
        </ListGroup>
      </Collapse>
    </Card>
  );
}

ListVisualizerField.propTypes = {
  fieldName: PropTypes.string.isRequired,
  fieldValue: PropTypes.arrayOf(
    PropTypes.shape({
      value: PropTypes.string.isRequired,
      valueColor: PropTypes.string,
      valueLink: PropTypes.string,
      valueClassName: PropTypes.string,
      valueAdditionalElement: PropTypes.element,
    })
  ).isRequired,
  titleColor: PropTypes.string,
  titleLink: PropTypes.string,
  titleClassName: PropTypes.string,
  titleAdditionalElement: PropTypes.element,
};

ListVisualizerField.defaultProps = {
  titleColor: "",
  titleLink: "",
  titleClassName: "",
  titleAdditionalElement: null,
};

export function VisualizerComponent({
  fieldName,
  fieldType,
  fieldValue,
  hideFalseValue,
}) {
  if (hideFalseValue === true) {
    /* the !! operator converts to bool, but empty arrays and objects return true.
         typeof of both dicts and lists return "object". we need a custom logic for arrays. */
    if (typeof fieldValue === "object") {
      if (Array.isArray(fieldValue)) {
        if (fieldValue.length === 0) {
          return null;
        }
      } else if (Object.keys(fieldValue).length === 0) {
        return null;
      }
    } else if (!!fieldValue === false) {
      return null;
    }
  }
  // choose the component
  let component = null;
  switch (fieldType) {
    case "list":
      component = (
        <ListVisualizerField
          fieldName={fieldName}
          fieldValue={fieldValue}
          titleClassName="mb-0"
        />
      );
      break;
    case "bool":
      component = (
        <BooleanVisualizerField fieldName={fieldName} fieldValue={fieldValue} />
      );
      break;
    default:
      component = (
        <StringVisualizerField
          fieldName={fieldName}
          fieldValue={fieldValue}
          titleClassName="text-capitalize mb-0"
          valueClassName="small mb-0 bg-dark"
        />
      );
  }
  return (
    <div key={fieldName} className="col-auto">
      {component}
    </div>
  );
}

VisualizerComponent.propTypes = {
  fieldName: PropTypes.string.isRequired,
  fieldType: PropTypes.string.isRequired,
  fieldValue: PropTypes.string.isRequired,
  hideFalseValue: PropTypes.bool,
};

VisualizerComponent.defaultProps = {
  hideFalseValue: false,
};
