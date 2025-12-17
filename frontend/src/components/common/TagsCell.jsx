import React from "react";
import PropTypes from "prop-types";
import { UncontrolledTooltip, Badge } from "reactstrap";
import { BsFillPlusCircleFill } from "react-icons/bs";

import { TagsBadge } from "./engineBadges";

export default function TagsCell({ values, rowId }) {
  let lastTags = null;
  if (values?.length > 10) {
    lastTags = values?.slice(10, values.length);
  }

  return values ? (
    <div className="d-flex justify-content-center py-2 flex-wrap">
      {values?.slice(0, 9).map((tag, index) => (
        <TagsBadge
          id={`row${rowId}_${index}`}
          tag={tag}
          className="ms-1 mb-1"
        />
      ))}
      {lastTags && (
        <Badge id="last_tags" className="d-flex-center ms-1 mb-1">
          <BsFillPlusCircleFill />
          <UncontrolledTooltip target="last_tags" placement="top" fade={false}>
            {lastTags.toString()}
          </UncontrolledTooltip>
        </Badge>
      )}
    </div>
  ) : (
    <div />
  );
}

TagsCell.propTypes = {
  values: PropTypes.array.isRequired,
  rowId: PropTypes.string.isRequired,
};
