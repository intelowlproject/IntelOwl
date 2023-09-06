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

  return (
    <div className={size} id={id}>
      <Card className={disable ? "opacity-50" : ""}>
        <CardTitle className="p-1 mb-0">
          <Button
            className="p-0 w-100 px-1"
            onClick={toggleList}
            color={name.props.color.replace("bg-", "")}
          >
            <div
              className={`d-flex align-items-center text-capitalize justify-content-${alignment}`}
            >
              {name}
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
    </div>
  );
}

VerticalListVisualizer.propTypes = {
  size: PropTypes.string.isRequired,
  name: PropTypes.element.isRequired,
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
};
