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

  const tableId = job ? `table-user-${job.id}` : `table-user-${value}`;
  const tableKey = job ? `table-user-${job.id}` : `table-user-${value}`;

  return (
    <div>
      {isCopyToClipboard ? (
        <CopyToClipboardButton
          showOnHover
          id={tableId}
          key={tableKey}
          text={value}
          className={`d-block p-2 ${
            isTruncate ? `text-truncate` : `text-break`
          }`}
        >
          {value}
        </CopyToClipboardButton>
      ) : (
        <div className="d-flex justify-content-center">
          <span className="d-block text-break pb-2" id={tableId} key={tableKey}>
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
