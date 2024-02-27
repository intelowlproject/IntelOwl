import { CopyToClipboardButton } from "@certego/certego-ui";
import React from "react";
import PropTypes from "prop-types";
import truncateText from "../../utils/truncateText";

export default function TableCellList(props) {
  const {
    value = [],
    size = null,
    idPrefix = null,
    keyPrefix = null,
    ulKey = null,
  } = props;

  return (
    <ul
      className="d-flex flex-column align-items-start text-left text-truncate"
      key={ulKey}
    >
      {value?.sort().map((val) => (
        <li
          className="mb-1 pb-2"
          key={keyPrefix ? `${keyPrefix}${val}` : val}
          id={idPrefix ? `${idPrefix}${val}` : val}
        >
          <CopyToClipboardButton
            showOnHover
            text={val}
            className="d-block text-truncate"
          >
            {truncateText(val, size || 20)}
          </CopyToClipboardButton>
        </li>
      ))}
    </ul>
  );
}

TableCellList.propTypes = {
  value: PropTypes.arrayOf(PropTypes.string),
  size: PropTypes.number,
  idPrefix: PropTypes.string,
  keyPrefix: PropTypes.string,
  ulKey: PropTypes.string,
};

TableCellList.defaultProps = {
  value: [],
  size: null,
  idPrefix: null,
  keyPrefix: null,
  ulKey: null,
};
