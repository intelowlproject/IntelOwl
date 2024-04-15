import React from "react";
import PropTypes from "prop-types";
import { Spinner } from "reactstrap";
import {
  MdDeleteOutline,
  MdOutlineRefresh,
  MdComment,
  MdFileDownload,
} from "react-icons/md";
import { FaRegStopCircle } from "react-icons/fa";

// These function are needed in IconButton because it expects Icon as a function

export function DeleteIcon() {
  return (
    <span>
      <MdDeleteOutline className="text-danger me-1" />
      Delete
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

export function SpinnerIcon() {
  return <Spinner type="border" size="sm" className="text-darker" />;
}

export function killJobIcon() {
  return (
    <span>
      <FaRegStopCircle className="me-1" />
      Kill job
    </span>
  );
}
