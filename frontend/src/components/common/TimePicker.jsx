import React from "react";
import { Input, Label } from "reactstrap";
import { format } from "date-fns";
import { useTimePickerStore } from "../../stores/useTimePickerStore";
import { datetimeFormatStr } from "../../constants/miscConst";

export function TimePicker() {
  const [toDateValue, fromDateValue, updateToDate, updateFromDate] =
    useTimePickerStore((state) => [
      state.toDateValue,
      state.fromDateValue,
      state.updateToDate,
      state.updateFromDate,
    ]);

  return (
    <div className="d-flex float-end">
      <div className="d-flex align-items-center">
        <Label className="me-1 mb-0" for="DatePicker__gte">
          From:
        </Label>
        <Input
          id="DatePicker__gte"
          type="datetime-local"
          name="received_request_time__gte"
          autoComplete="off"
          value={format(fromDateValue, datetimeFormatStr)}
          onChange={(event) => {
            updateFromDate(new Date(event.target.value));
          }}
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
          name="received_request_time__lte"
          autoComplete="off"
          value={format(toDateValue, datetimeFormatStr)}
          onChange={(event) => {
            updateToDate(new Date(event.target.value));
          }}
          min="1970-01-01T00:00:00"
        />
      </div>
    </div>
  );
}
