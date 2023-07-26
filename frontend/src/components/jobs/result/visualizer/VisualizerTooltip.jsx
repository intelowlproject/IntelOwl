import React from "react";
import PropTypes from "prop-types";
import { CopyToClipboardButton } from "@certego/certego-ui";
import { Button, UncontrolledTooltip } from "reactstrap";
import { MdContentCopy } from "react-icons/md";
import { AiOutlineLink } from "react-icons/ai";

export function VisualizerTooltip({
  idElement,
  copyText,
  link,
  description,
  disable,
}) {
  return (
    <UncontrolledTooltip target={idElement} placement="right" autohide={false}>
      <div className="p-0 my-2 d-flex justify-content-start">
        <CopyToClipboardButton
          id={idElement}
          text={copyText}
          className="mx-1 p-2 btn btn-secondary btn-sm"
        >
          <MdContentCopy /> Copy
        </CopyToClipboardButton>
        <Button
          className="mx-1 p-2"
          size="sm"
          disabled={disable || !link}
          href={link}
          target="_blank"
          rel="noreferrer"
        >
          <AiOutlineLink /> Link
        </Button>
      </div>
      {description && (
        <div
          className="bg-body p-3 py-2 mb-1 text-start"
          style={{ maxWidth: "400px" }}
        >
          <small>{description}</small>
        </div>
      )}
    </UncontrolledTooltip>
  );
}

VisualizerTooltip.propTypes = {
  idElement: PropTypes.string.isRequired,
  copyText: PropTypes.string,
  description: PropTypes.string,
  link: PropTypes.string,
  disable: PropTypes.bool,
};

VisualizerTooltip.defaultProps = {
  copyText: "",
  link: "",
  disable: false,
  description: "",
};
