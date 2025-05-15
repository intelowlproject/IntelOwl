import React from "react";
import { Button } from "reactstrap";
import PropTypes from "prop-types";
import { FaFileDownload } from "react-icons/fa";
import { fileDownload, humanReadbleSize } from "../../../../utils/files";
import { VisualizerTooltip } from "../VisualizerTooltip";

export function DownloadVisualizer({
  size,
  alignment,
  disable,
  id,
  value,
  mimetype,
  payload,
  isChild,
  copyText,
  description,
  addMetadataInDescription,
  link,
}) {
  const blobFile = new Blob([payload], { type: mimetype });
  let finalDescription = description;
  if (addMetadataInDescription) {
    finalDescription += `\n\n**Mimetype**: ${mimetype}. **Size**: ${humanReadbleSize(
      blobFile.size,
    )}`;
  }

  return (
    <>
      <div
        className={`${size} ${
          isChild ? "small" : ""
        } p-0 m-1 d-flex align-items-center text-${alignment} justify-content-${alignment} ${
          disable ? "opacity-25" : ""
        }`}
        id={id}
      >
        <Button
          onClick={() => {
            const blob = blobFile;
            if (!blob) return;
            fileDownload(blob, value);
          }}
          id={`${id}-tooltip`}
          disabled={disable}
        >
          <FaFileDownload />
          <span className={`${isChild ? "small" : ""}`}>{value}</span>
        </Button>
      </div>
      <VisualizerTooltip
        idElement={`${id}-tooltip`}
        copyText={copyText}
        link={link}
        disable={disable}
        description={finalDescription}
      />
    </>
  );
}

DownloadVisualizer.propTypes = {
  size: PropTypes.string.isRequired,
  alignment: PropTypes.string,
  disable: PropTypes.bool,
  id: PropTypes.string.isRequired,
  value: PropTypes.string.isRequired,
  mimetype: PropTypes.string.isRequired,
  payload: PropTypes.string.isRequired,
  isChild: PropTypes.bool,
  copyText: PropTypes.string,
  description: PropTypes.string,
  addMetadataInDescription: PropTypes.bool,
  link: PropTypes.string,
};

DownloadVisualizer.defaultProps = {
  alignment: "center",
  disable: false,
  isChild: false,
  copyText: "",
  description: "",
  addMetadataInDescription: true,
  link: "",
};
