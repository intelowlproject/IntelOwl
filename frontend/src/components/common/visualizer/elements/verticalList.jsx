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
  alignment,
  name,
  values,
  startOpen,
  disable,
  id,
}) {
  const [isListOpen, setIsListOpen] = useState(startOpen);
  const toggleList = () => setIsListOpen(!isListOpen);
  let color = "";
  if (name) color = name.props.color.replace("bg-", "");

  return (
    <div className={size} id={id}>
      {name ? (
        <Card className={`${disable ? "opacity-50" : ""} border-${color}`}>
          <CardTitle className="p-1 mb-0">
            <Button
              className="p-0 w-100 px-1"
              onClick={toggleList}
              color={color}
            >
              <div
                className={`d-flex flex-wrap align-items-center text-capitalize justify-content-${alignment}`}
              >
                <div className="text-break">{name}</div>
                {isListOpen ? (
                  <IoIosArrowDropupCircle className="ms-1" />
                ) : (
                  <IoIosArrowDropdownCircle className="ms-1" />
                )}
              </div>
            </Button>
          </CardTitle>
          <Collapse isOpen={isListOpen}>
            <ListGroup flush>
              {values.map((listElement, index) => (
                <ListGroupItem
                  key={`${id}-${listElement.props.value}`}
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
      ) : (
        <ListGroup flush>
          {values.map((listElement) => (
            <ListGroupItem
              key={`${id}-${listElement.props.value}`}
              className={`${listElement.props.color} border-dark`}
            >
              {listElement}
            </ListGroupItem>
          ))}
        </ListGroup>
      )}
    </div>
  );
}

VerticalListVisualizer.propTypes = {
  size: PropTypes.string.isRequired,
  name: PropTypes.element,
  values: PropTypes.arrayOf(PropTypes.element).isRequired,
  alignment: PropTypes.string,
  startOpen: PropTypes.bool,
  disable: PropTypes.bool,
  id: PropTypes.string.isRequired,
};

VerticalListVisualizer.defaultProps = {
  alignment: "",
  startOpen: false,
  disable: false,
  name: null,
};
