import React from "react";
import PropTypes from "prop-types";
import { Button, Collapse } from "reactstrap";
import { ArrowToggleIcon, CopyToClipboardButton } from "@certego/certego-ui";

export function TableCellCollapse({ values, label }) {
  // local state
  const [isOpen, setIsOpen] = React.useState(false);
  return (
    <div>
      <Button
        className="bg-transparent border-0"
        onClick={() => setIsOpen(!isOpen)}
        id="table-cell-collapse"
      >
        <small>
          {values?.length} {label}{" "}
        </small>
        <ArrowToggleIcon isExpanded={isOpen} />
      </Button>
      <Collapse isOpen={isOpen} id="table-cell-collapse">
        <ul className="d-flex flex-column align-items-start p-3">
          {values?.sort().map((value, index) => (
            <li className="pb-2" key={value}>
              <CopyToClipboardButton
                id={`table-cell-collapse__${index}`}
                showOnHover
                text={value}
                className="d-block text-break"
              >
                {value}
              </CopyToClipboardButton>
            </li>
          ))}
        </ul>
      </Collapse>
    </div>
  );
}

TableCellCollapse.propTypes = {
  values: PropTypes.array.isRequired,
  label: PropTypes.string.isRequired,
};
