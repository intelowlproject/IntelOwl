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
  size,
  name,
  values,
  className,
  startOpen,
  disable,
}) {
  const [isListOpen, setIsListOpen] = useState(startOpen);
  const toggleList = () => setIsListOpen(!isListOpen);

  return (
    <div className={`${size}`}>
      <Card className={`${className} ${disable ? "opacity-50" : ""}`}>
        <CardTitle className="p-1 mb-0">
          <Button
            className="p-0 w-100 px-1"
            onClick={toggleList}
            color={name.props.color.replace("bg-", "")}
            disabled={disable}
          >
            <div className="d-flex align-items-center">
              {isListOpen ? (
                <IoIosArrowDropupCircle className="me-1" />
              ) : (
                <IoIosArrowDropdownCircle className="me-1" />
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
                className={`text-break ${
                  index === values.length - 1 ? "rounded-bottom" : ""
                } ${listElement.props.color}`}
              >
                {listElement}
              </ListGroupItem>
            ))}
          </ListGroup>
        </Collapse>
      </Card>
    </div>
  );
}

VerticalListVisualizer.propTypes = {
  size: PropTypes.string.isRequired,
  name: PropTypes.element.isRequired,
  values: PropTypes.arrayOf(PropTypes.element).isRequired,
  className: PropTypes.string,
  startOpen: PropTypes.bool,
  disable: PropTypes.bool,
};

VerticalListVisualizer.defaultProps = {
  className: "",
  startOpen: false,
  disable: false,
};
