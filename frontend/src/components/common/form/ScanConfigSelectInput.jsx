import React from "react";
import PropTypes from "prop-types";
import { FormGroup, Input, Label, UncontrolledTooltip } from "reactstrap";
import { MdInfoOutline } from "react-icons/md";

import { ScanModesNumeric } from "../../../constants/advancedSettingsConst";

export function ScanConfigSelectInput(props) {
  const { formik } = props;
  console.debug("ScanConfigSelectInput - formik:");
  console.debug(formik);

  return (
    <div>
      <FormGroup
        check
        key="checkchoice__check_all"
        className="d-flex align-items-center justify-content-between"
      >
        <div>
          <Input
            id="checkchoice__check_all"
            type="radio"
            name="scan_mode"
            value={ScanModesNumeric.CHECK_PREVIOUS_ANALYSIS}
            onChange={formik.handleChange}
            checked={
              formik.values.scan_mode ===
              ScanModesNumeric.CHECK_PREVIOUS_ANALYSIS
            }
          />
          <Label check for="checkchoice__check_all">
            Do not execute if a similar analysis is currently running or
            reported without fails
          </Label>
        </div>
        <div className="col-3 d-flex align-items-center">
          H:
          <div className="col-8 mx-1">
            <Input
              id="checkchoice__check_all__minutes_ago"
              type="number"
              name="scan_check_time"
              value={formik.values.scan_check_time}
              onChange={formik.handleChange}
            />
          </div>
          <div className="col-2">
            <MdInfoOutline id="minutes-ago-info-icon" />
            <UncontrolledTooltip
              target="minutes-ago-info-icon"
              placement="right"
              fade={false}
              innerClassName="p-2 border border-info text-start text-nowrap md-fit-content"
            >
              <span>
                Max age (in hours) for the similar analysis.
                <br />
                The default value is 24 hours (1 day).
                <br />
                Empty value takes all the previous analysis.
              </span>
            </UncontrolledTooltip>
          </div>
        </div>
      </FormGroup>

      <FormGroup check key="checkchoice__force_new">
        <Input
          id="checkchoice__force_new"
          type="radio"
          name="scan_mode"
          value={ScanModesNumeric.FORCE_NEW_ANALYSIS}
          onChange={formik.handleChange}
          checked={
            formik.values.scan_mode === ScanModesNumeric.FORCE_NEW_ANALYSIS
          }
        />
        <Label check for="checkchoice__force_new">
          Force new analysis
        </Label>
      </FormGroup>
    </div>
  );
}

ScanConfigSelectInput.propTypes = {
  formik: PropTypes.object.isRequired,
};
