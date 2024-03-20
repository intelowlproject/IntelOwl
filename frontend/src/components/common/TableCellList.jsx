import { CopyToClipboardButton } from "@certego/certego-ui";
import React from "react";
import PropTypes from "prop-types";

export default function TableCellList(props) {
  const { value = [], idPrefix = null, keyPrefix = null, ulKey = null } = props;

  return (
    <ul className="d-flex flex-column text-left" key={ulKey}>
      {value?.sort().map((val, index) => (
        <li
          className="mb-1 pb-2"
          key={keyPrefix ? `${keyPrefix}${index}` : index}
          id={idPrefix ? `${idPrefix}${val}` : val}
        >
          <div className="d-flex align-items-start">
            <CopyToClipboardButton
              showOnHover
              text={val}
              className="d-block text-break"
            >
              {val}
            </CopyToClipboardButton>
          </div>
        </li>
      ))}
    </ul>
  );
}

TableCellList.propTypes = {
  value: PropTypes.arrayOf(PropTypes.string),
  idPrefix: PropTypes.string,
  keyPrefix: PropTypes.string,
  ulKey: PropTypes.string,
};

TableCellList.defaultProps = {
  value: [],
  idPrefix: null,
  keyPrefix: null,
  ulKey: null,
};
