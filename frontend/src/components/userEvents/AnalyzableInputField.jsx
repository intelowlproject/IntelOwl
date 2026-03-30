import React from "react";
import PropTypes from "prop-types";
import { Col, Input, Button, FormFeedback } from "reactstrap";
import { BsFillTrashFill, BsFillPlusCircleFill } from "react-icons/bs";
import { useDebounceInput } from "@certego/certego-ui";

import { AnalyzableInputInfo, detectInputType } from "./userEventFormUtils";
import { useAuthStore } from "../../stores/useAuthStore";

export function AnalyzableInputField({
  index,
  arrayHelpers,
  initialValue,
  formik,
  setInputTypes,
}) {
  console.debug("AnalyzableInputField rendered!");

  // store
  const [user] = useAuthStore((state) => [state.user]);
  // local state
  const [userInput, setUserInput] = React.useState(""); // user typing
  const [debounceInput, setDebounceInput] = React.useState(""); // input debounce
  const [extraInfo, setExtraInfo] = React.useState(undefined); // extra input info
  const [extraInfoLoading, setExtraInfoLoading] = React.useState(false);

  // debounce
  const debounceFunc = (input) => {
    if (input !== "" && input !== userInput) {
      // only update local state, not formik
      setDebounceInput(input);
    } else if (input !== "") {
      // update local state and formik
      const attributevalues = formik.values.analyzables;
      attributevalues[index] = input;
      formik.setFieldValue("analyzables", attributevalues, false);
      setDebounceInput(input);
    }
  };
  useDebounceInput(userInput, 1000, debounceFunc);

  React.useEffect(() => {
    const fetchData = async () => {
      if (debounceInput !== "") {
        try {
          setExtraInfoLoading(true);
          const inputData = await detectInputType({
            value: debounceInput,
            user,
          });
          setExtraInfo(inputData);
          setExtraInfoLoading(false);
          setInputTypes((prevState) => ({
            ...prevState,
            [debounceInput]: inputData,
          }));
        } catch (error) {
          // already saved in inputState
        }
      }
    };
    fetchData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debounceInput]);

  React.useEffect(() => {
    setUserInput(initialValue);
  }, [initialValue]);

  // onChange func
  const analyzableOnChange = (value) => setUserInput(value);

  return (
    <div key={`analyzables-${index + 0}`}>
      <div className="py-2 d-flex">
        <Col sm={10} className="pe-3">
          <Input
            type="text"
            id={`analyzables-${index}`}
            name={`analyzables-${index}`}
            placeholder="google.com, 8.8.8.8, https://google.com, 1d5920f4b44b27a802bd77c4f0536f5a, .*\.com"
            className="input-dark"
            value={userInput}
            onBlur={formik.handleBlur}
            onChange={(event) => analyzableOnChange(event.target.value)}
            invalid={
              formik.touched[`analyzables-${index}`] &&
              formik.errors[`analyzables-${index}`]
            }
          />
          <FormFeedback>{formik.errors[`analyzables-${index}`]}</FormFeedback>
        </Col>
        <Col sm={2} className="d-flex justify-content-start">
          <Button
            color="primary"
            size="sm"
            id={`analyzables-${index}-deletebtn`}
            className="mx-1 rounded-1 d-flex align-items-center px-3"
            onClick={() => {
              if (index + 1 < formik.values.analyzables.lenght) {
                setDebounceInput(formik.values.analyzables[index + 1]);
                arrayHelpers.remove(index);
              } else {
                arrayHelpers.remove(index);
              }
            }}
            disabled={formik.values.analyzables.length === 1}
          >
            <BsFillTrashFill />
          </Button>
          <Button
            color="primary"
            size="sm"
            id={`analyzables-${index}-addbtn`}
            className="mx-1 rounded-1 d-flex align-items-center px-3"
            onClick={() => {
              arrayHelpers.push("");
            }}
            disabled={
              formik.values.analyzables.length === 1 &&
              formik.values.analyzables[0] === ""
            }
          >
            <BsFillPlusCircleFill />
          </Button>
        </Col>
      </div>
      <AnalyzableInputInfo data={extraInfo} isLoading={extraInfoLoading} />
    </div>
  );
}

AnalyzableInputField.propTypes = {
  index: PropTypes.number.isRequired,
  arrayHelpers: PropTypes.object.isRequired,
  initialValue: PropTypes.string.isRequired,
  formik: PropTypes.object.isRequired,
  setInputTypes: PropTypes.func.isRequired,
};
