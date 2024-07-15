import React from "react";
import { Input, Label } from "reactstrap";
import { useTimePickerStore } from "../../stores/useTimePickerStore";

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
        <Label className="me-2 mb-0" for="DatePicker__gte">
          From:
        </Label>
        <Input
          id="DatePicker__gte"
          type="date"
          name="received_request_time__gte"
          autoComplete="off"
          value={fromDateValue.toISOString().split("T")[0]}
          onChange={(event) => {
            updateFromDate(new Date(event.target.value));
          }}
        />
      </div>
      <div className="d-flex align-items-center">
        <Label className="mx-2 mb-0" for="DatePicker__lte">
          To:
        </Label>
        <Input
          id="DatePicker__lte"
          type="date"
          name="received_request_time__lte"
          autoComplete="off"
          value={toDateValue.toISOString().split("T")[0]}
          onChange={(event) => {
            updateToDate(new Date(event.target.value));
          }}
        />
      </div>
    </div>
  );
}
