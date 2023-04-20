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

export function VerticalListVisualizer({
  name,
  values,
  className,
  startOpen,
  hideIfEmpty,
  disableIfEmpty,
}) {
  const [isListOpen, setIsListOpen] = useState(startOpen);
  const toggleList = () => setIsListOpen(!isListOpen);

  if (hideIfEmpty && values.length === 0) {
    return null;
  }
  let isDisabled = false;
  if (disableIfEmpty && values.length === 0) {
    isDisabled = true;
  }

  return (
    <Card
      className={`${className} ${
        isDisabled ? "visualizer-element-disabled" : ""
      }`}
    >
      <CardTitle className="p-1 mb-0">
        <Button
          className="p-0 w-100"
          onClick={toggleList}
          color={name.props.color.replace("bg-", "")}
          disabled={isDisabled}
        >
          <div className="d-flex align-items-center">
            {isListOpen ? (
              <IoIosArrowDropupCircle className="mx-1" />
            ) : (
              <IoIosArrowDropdownCircle className="mx-1" />
            )}
            {name}
          </div>
        </Button>
      </CardTitle>
      <Collapse isOpen={isListOpen}>
        <ListGroup flush>
          {values.map((listElement, index) => (
            <ListGroupItem
              key={listElement.value}
              className={index === values.length - 1 ? "rounded-bottom" : ""}
            >
              {listElement}
            </ListGroupItem>
          ))}
        </ListGroup>
      </Collapse>
    </Card>
  );
}

VerticalListVisualizer.propTypes = {
  name: PropTypes.string.isRequired,
  values: PropTypes.arrayOf(PropTypes.element).isRequired,
  className: PropTypes.string,
  startOpen: PropTypes.bool,
  hideIfEmpty: PropTypes.bool,
  disableIfEmpty: PropTypes.bool,
};

VerticalListVisualizer.defaultProps = {
  className: "",
  startOpen: false,
  hideIfEmpty: false,
  disableIfEmpty: false,
};
