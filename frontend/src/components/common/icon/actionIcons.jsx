import React from "react";
import { Spinner } from "reactstrap";
import { FaRegStopCircle } from "react-icons/fa";
import { BsFillPlusCircleFill } from "react-icons/bs";
import { GoCommentDiscussion } from "react-icons/go";

// These function are needed in IconButton because it expects Icon as a function

export function CommentIcon() {
  return (
    <span className="d-flex align-items-center">
      <GoCommentDiscussion className="me-1" />
      Comments
    </span>
  );
}

export function SpinnerIcon() {
  return <Spinner type="border" size="sm" className="text-darker" />;
}

export function killJobIcon() {
  return (
    <span className="d-flex align-items-center">
      <FaRegStopCircle className="me-1" />
      Kill job
    </span>
  );
}

export function addEvaluationIcon() {
  return (
    <span className="d-flex align-items-center">
      <BsFillPlusCircleFill className="me-1" />
      Your evaluation
    </span>
  );
}
