import { CopyToClipboardButton } from "@certego/certego-ui";
import React from "react";
import PropTypes from "prop-types";

export default function TableCell(props) {
  const {
    value = null,
    isTruncate = false,
    isCopyToClipboard = false,
    isList = false,
    id,
    ulKey = null,
  } = props;

  let cell = (
    <div className="d-flex justify-content-center">
      <span
        className={`d-block p-2 ${isTruncate ? `text-truncate` : `text-break`}`}
        id={id}
      >
        {value}
      </span>
    </div>
  );

  if (isCopyToClipboard) {
    cell = (
      <CopyToClipboardButton
        showOnHover
        id={id}
        text={value}
        className={`d-block p-2 ${isTruncate ? `text-truncate` : `text-break`}`}
      >
        {value}
      </CopyToClipboardButton>
    );
  }

  if (isList) {
    cell = (
      <ul className="d-flex flex-column text-left" key={ulKey}>
        {value?.sort().map((val, index) => (
          <li
            className="mb-1 pb-2"
            key={`${id}__${val}`}
            id={`${id}__${index}`}
          >
            <div className="d-flex align-items-start">
              <CopyToClipboardButton
                id={`${id}__${index}`}
                showOnHover
                text={val}
                className={`d-block ${
                  isTruncate ? `text-truncate` : `text-break`
                }`}
              >
                {val}
              </CopyToClipboardButton>
            </div>
          </li>
        ))}
      </ul>
    );
  }

  return <div>{cell}</div>;
}

TableCell.propTypes = {
  value: PropTypes.any,
  isTruncate: PropTypes.bool,
  isCopyToClipboard: PropTypes.bool,
  isList: PropTypes.bool,
  id: PropTypes.string.isRequired,
  ulKey: PropTypes.string,
};

TableCell.defaultProps = {
  value: null,
  isTruncate: false,
  isCopyToClipboard: false,
  isList: false,
  ulKey: null,
};
