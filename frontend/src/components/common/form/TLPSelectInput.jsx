import React from "react";
import PropTypes from "prop-types";
import {
  FormGroup,
  Input,
  Label,
  UncontrolledTooltip,
  FormText,
} from "reactstrap";
import { Link } from "react-router-dom";
import { MdInfoOutline } from "react-icons/md";

import { TLPDescriptions } from "../../../constants/miscConst";
import { TlpChoices } from "../../../constants/advancedSettingsConst";
import { TLPTag } from "../TLPTag";
import { TLPColors } from "../../../constants/colorConst";
import { INTELOWL_DOCS_URL } from "../../../constants/environment";

export function TLPSelectInputLabel(props) {
  const { size } = props;

  return (
    <Label className="d-flex" sm={size}>
      TLP
      <div className="ms-2">
        <MdInfoOutline id="tlp-info-icon" />
        <UncontrolledTooltip
          target="tlp-info-icon"
          placement="right"
          fade={false}
          autohide={false}
          innerClassName="p-2 text-start text-nowrap md-fit-content"
        >
          <span>
            IntelOwl supports a customized version of the Traffic Light Protocol
            (TLP).
            <br />
            For more info check the{" "}
            <Link
              to={`${INTELOWL_DOCS_URL}IntelOwl/usage/#tlp-support`}
              target="_blank"
            >
              official doc.
            </Link>
          </span>
        </UncontrolledTooltip>
      </div>
    </Label>
  );
}

TLPSelectInputLabel.propTypes = {
  size: PropTypes.number.isRequired,
};

export function TLPSelectInput(props) {
  const { formik } = props;
  console.debug("TLPSelectInput - formik:");
  console.debug(formik);

  return (
    <div>
      <div>
        {TlpChoices.map((tlp) => (
          <FormGroup inline check key={`tlpchoice__${tlp}`}>
            <Label check for={`tlpchoice__${tlp}`}>
              <TLPTag value={tlp} />
            </Label>
            <Input
              id={`tlpchoice__${tlp}`}
              type="radio"
              name="tlp"
              value={tlp}
              invalid={formik.errors.tlp && formik.touched.tlp}
              onChange={formik.handleChange}
              checked={formik.values.tlp.includes(tlp)}
            />
          </FormGroup>
        ))}
      </div>
      <FormText>
        <span style={{ color: `${TLPColors[formik.values.tlp]}` }}>
          {TLPDescriptions[formik.values.tlp].replace("TLP: ", "")}
        </span>
      </FormText>
    </div>
  );
}

TLPSelectInput.propTypes = {
  formik: PropTypes.object.isRequired,
};
