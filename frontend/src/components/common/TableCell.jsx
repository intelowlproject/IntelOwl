import { CopyToClipboardButton } from "@certego/certego-ui";
import React from "react";
import PropTypes from "prop-types";

export default function TableCell(props) {
  const {
    value = null,
    isTruncate = false,
    isCopyToClipboard = false,
    job,
  } = props;

  return (
    <div>
      {isCopyToClipboard && (
        <CopyToClipboardButton
          showOnHover
          id={`table-user-${job ? job.id : value}`}
          key={`table-user-${job ? job.id : value}`}
          text={value}
          className={`d-block p-2 ${
            isTruncate ? `text-truncate` : `text-break`
          }`}
        >
          {value}
        </CopyToClipboardButton>
      )}

      {!isCopyToClipboard && (
        <div className="d-flex justify-content-center">
          <span
            className="d-block text-break pb-2"
            id={`table-user-${job ? job.id : value}`}
            key={`table-user-${job ? job.id : value}`}
          >
            {value}
          </span>
        </div>
      )}
    </div>
  );
}

TableCell.propTypes = {
  value: PropTypes.string,
  isTruncate: PropTypes.bool,
  isCopyToClipboard: PropTypes.bool,
  job: PropTypes.object,
};

TableCell.defaultProps = {
  value: null,
  isTruncate: false,
  isCopyToClipboard: false,
  job: null,
};
