import React from "react";
import PropTypes from "prop-types";
import { Badge } from "reactstrap";
// Card, CardHeader, CardBody, CardText

export function StringVisualizerField({fieldName, fieldValue}) {
    // return (
    //     <Card>
    //         <CardHeader>{fieldName}</CardHeader>
    //         <CardBody>
    //             <CardText>{fieldValue}</CardText>
    //         </CardBody>
    //     </Card>
    // );
    return (
        <div>
            <small className="fw-bold text-light">{fieldName}</small>
            <div className="bg-dark p-1 text-light">{fieldValue}</div>
        </div>
    );
}

StringVisualizerField.propTypes = {
    fieldName: PropTypes.string.isRequired,
    fieldValue: PropTypes.string.isRequired,
};

export function BooleanVisualizerField({fieldName, fieldValue}) {
    return <Badge pill color={fieldValue === true ? "danger" : "gray"}>{fieldName.replaceAll("_", " ")}</Badge>
}

BooleanVisualizerField.propTypes = {
    fieldName: PropTypes.string.isRequired,
    fieldValue: PropTypes.bool.isRequired,
};
