import React from "react";
import PropTypes from "prop-types";
import { Button, Collapse } from "reactstrap";
import { ArrowToggleIcon, CopyToClipboardButton } from "@certego/certego-ui";

export function ErrorsCollapse({ errors }) {
  // local state
  const [isOpen, setIsOpen] = React.useState(false);
  return (
    <div>
      <Button
        className="bg-transparent border-0"
        onClick={() => setIsOpen(!isOpen)}
        id="ReportErrorsDropDown"
      >
        <small>{errors.length} errors </small>
        <ArrowToggleIcon isExpanded={isOpen} />
      </Button>
      <Collapse isOpen={isOpen} id="ReportErrorsDropDown">
        <ul className="d-flex flex-column align-items-start p-3">
          {errors?.sort().map((error) => (
            <li className="pb-2" key={error}>
              <CopyToClipboardButton
                showOnHover
                text={error}
                className="d-block text-break"
              >
                {error}
              </CopyToClipboardButton>
            </li>
          ))}
        </ul>
      </Collapse>
    </div>
  );
}

ErrorsCollapse.propTypes = {
  errors: PropTypes.array.isRequired,
};
