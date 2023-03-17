import React, { useState } from "react";
import PropTypes from "prop-types";

import {
  Button,
  Card,
  CardTitle,
  Collapse,
  ListGroup,
  ListGroupItem,
} from "reactstrap";
import {
  IoIosArrowDropupCircle,
  IoIosArrowDropdownCircle,
} from "react-icons/io";

import { BaseVisualizerField } from "./base";

export function ListVisualizerField({
  name,
  values,
  color,
  link,
  className,
  additionalElements,
  startOpen,
  hideIfEmpty,
  disableIfEmpty,
}) {
  const [isListOpen, setIsListOpen] = useState(startOpen);
  const toggleList = () => setIsListOpen(!isListOpen);

  console.debug("ListVisualizerField.fieldValue");
  console.debug(values);

  if (hideIfEmpty && values.length === 0) {
    return null;
  }
  let isDisabled = false;
  if (disableIfEmpty && values.length === 0) {
    isDisabled = true;
  }

  return (
    <div key={name} className="col-auto">
      <Card className={isDisabled ? "visualizer-element-disabled" : ""}>
        <CardTitle className="p-1 mb-0">
          <Button
            className="p-0 w-100"
            onClick={toggleList}
            color={color}
            disabled={isDisabled}
          >
            <div className="d-flex align-items-center">
              {isListOpen ? (
                <IoIosArrowDropupCircle className="mx-1" />
              ) : (
                <IoIosArrowDropdownCircle className="mx-1" />
              )}
              <BaseVisualizerField
                value={name}
                link={link}
                className={className}
                additionalElements={additionalElements}
              />
            </div>
          </Button>
        </CardTitle>
        <Collapse isOpen={isListOpen}>
          <ListGroup flush>
            {values.map((listElement) => (
              <ListGroupItem key={listElement.value}>
                {listElement}
              </ListGroupItem>
            ))}
          </ListGroup>
        </Collapse>
      </Card>
    </div>
  );
}

ListVisualizerField.propTypes = {
  name: PropTypes.string.isRequired,
  values: PropTypes.arrayOf(PropTypes.object).isRequired,
  color: PropTypes.string,
  link: PropTypes.string,
  className: PropTypes.string,
  additionalElements: PropTypes.arrayOf(PropTypes.object),
  startOpen: PropTypes.bool,
  hideIfEmpty: PropTypes.bool,
  disableIfEmpty: PropTypes.bool,
};

ListVisualizerField.defaultProps = {
  color: "",
  link: "",
  className: "",
  additionalElements: null,
  startOpen: false,
  hideIfEmpty: false,
  disableIfEmpty: false,
};
