import React from "react";
import { Col, FormGroup, Button, Input } from "reactstrap";
import PropTypes from "prop-types";
import { FieldArray } from "formik";
import { BsFillTrashFill, BsFillPlusCircleFill } from "react-icons/bs";

export function ListInput({
  id,
  values,
  formikSetFieldValue,
  placeholder,
  formikHandlerBlur,
  disabled,
}) {
  return (
    <FieldArray
      name={id}
      render={(arrayHelpers) => (
        <FormGroup row>
          <div style={{ maxHeight: "30vh", overflowY: "scroll" }}>
            {values && values.length > 0
              ? values.map((value, index) => (
                  <div className="py-2 d-flex" key={`${id}-${index + 0}`}>
                    <Col sm={10} className="pe-3">
                      <Input
                        type="text"
                        id={`${id}-${index}`}
                        name={`${id}-${index}`}
                        placeholder={placeholder}
                        className="input-dark"
                        value={value}
                        onBlur={formikHandlerBlur}
                        onChange={(event) => {
                          const attributevalues = values;
                          attributevalues[index] = event.target.value;
                          formikSetFieldValue(`${id}`, attributevalues, true);
                        }}
                        disabled={disabled}
                      />
                    </Col>
                    <Col sm={2} className="d-flex justify-content-start">
                      <Button
                        color="primary"
                        size="sm"
                        id={`${id}-${index}-deletebtn`}
                        className="mx-1 rounded-1 d-flex align-items-center px-3"
                        onClick={() => arrayHelpers.remove(index)}
                        disabled={values.length === 1}
                      >
                        <BsFillTrashFill />
                      </Button>
                      <Button
                        color="primary"
                        size="sm"
                        id={`${id}-${index}-addbtn`}
                        className="mx-1 rounded-1 d-flex align-items-center px-3"
                        onClick={() => arrayHelpers.push("")}
                      >
                        <BsFillPlusCircleFill />
                      </Button>
                    </Col>
                  </div>
                ))
              : null}
          </div>
        </FormGroup>
      )}
    />
  );
}

ListInput.propTypes = {
  id: PropTypes.string.isRequired,
  values: PropTypes.array.isRequired,
  formikSetFieldValue: PropTypes.func.isRequired,
  placeholder: PropTypes.string,
  formikHandlerBlur: PropTypes.func.isRequired,
  disabled: PropTypes.bool,
};

ListInput.defaultProps = {
  placeholder: "",
  disabled: false,
};
