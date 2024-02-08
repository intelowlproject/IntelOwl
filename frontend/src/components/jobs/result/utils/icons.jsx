import React from "react";
import PropTypes from "prop-types";
import {
  MdDeleteOutline,
  MdOutlineRefresh,
  MdComment,
  MdFileDownload,
} from "react-icons/md";

export function DeleteIcon() {
  return (
    <span>
      <MdDeleteOutline className="text-danger" /> Delete Job
    </span>
  );
}

export function CommentIcon({ commentNumber }) {
  return (
    <span>
      <MdComment className="me-1" />
      Comments ({commentNumber})
    </span>
  );
}

CommentIcon.propTypes = {
  commentNumber: PropTypes.number.isRequired,
};

export function retryJobIcon() {
  return (
    <span>
      <MdOutlineRefresh className="me-1" />
      Rescan
    </span>
  );
}

export function downloadReportIcon() {
  return (
    <span>
      <MdFileDownload className="me-1" />
      Report
    </span>
  );
}
