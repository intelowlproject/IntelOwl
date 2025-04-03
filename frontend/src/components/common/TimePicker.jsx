import React from "react";
import PropTypes from "prop-types";
import { Label, Input } from "reactstrap";
import { format } from "date-fns-tz";

import { datetimeFormatStr } from "../../constants/miscConst";

export function TimePicker(props) {
  const { id, fromName, toName, fromValue, toValue, fromOnChange, toOnChange } =
    props;

  return (
    <div id={id} className="d-flex float-end">
      <div className="d-flex align-items-center">
        <Label className="me-1 mb-0" for="DatePicker__gte">
          From:
        </Label>
        <Input
          id="DatePicker__gte"
          type="datetime-local"
          name={fromName}
          autoComplete="off"
          value={format(fromValue, datetimeFormatStr)}
          onChange={(event) =>
            event.target.value === ""
              ? fromOnChange(format(toValue, datetimeFormatStr))
              : fromOnChange(
                  format(new Date(event.target.value), datetimeFormatStr),
                )
          }
          min="1970-01-01T00:00:00"
        />
      </div>
      <div className="d-flex align-items-center ms-1">
        <Label className="me-1 mb-0" for="DatePicker__lte">
          To:
        </Label>
        <Input
          id="DatePicker__lte"
          type="datetime-local"
          name={toName}
          autoComplete="off"
          value={format(toValue, datetimeFormatStr)}
          onChange={(event) =>
            event.target.value === ""
              ? toOnChange(format(new Date(), datetimeFormatStr))
              : toOnChange(
                  format(new Date(event.target.value), datetimeFormatStr),
                )
          }
          min="1970-01-01T00:00:00"
        />
      </div>
    </div>
  );
}

TimePicker.propTypes = {
  id: PropTypes.string.isRequired,
  fromName: PropTypes.string.isRequired,
  toName: PropTypes.string.isRequired,
  fromValue: PropTypes.any.isRequired,
  toValue: PropTypes.any.isRequired,
  fromOnChange: PropTypes.func.isRequired,
  toOnChange: PropTypes.func.isRequired,
};
