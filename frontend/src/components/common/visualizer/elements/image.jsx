// This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
// See the file 'LICENSE' for copying permission.

import React from "react";
import PropTypes from "prop-types";
import { Modal, ModalBody, ModalHeader, UncontrolledTooltip } from "reactstrap";
import { MdBrokenImage, MdZoomIn } from "react-icons/md";

/**
 * ImageVisualizer component for displaying images in the visualizer.
 * Supports both URL and base64 encoded images.
 * Includes click-to-zoom functionality with a modal preview.
 */
export function ImageVisualizer({
  id,
  url,
  base64,
  title,
  description,
  maxWidth,
  maxHeight,
  allowExpand,
  disable,
  size,
}) {
  const [isModalOpen, setIsModalOpen] = React.useState(false);
  const [hasError, setHasError] = React.useState(false);
  const [isLoading, setIsLoading] = React.useState(true);

  // Determine the image source - URL takes precedence over base64
  const imageSrc = React.useMemo(() => {
    if (url) return url;
    if (base64) {
      // Handle base64 with or without data URI prefix
      if (base64.startsWith("data:")) {
        return base64;
      }
      // Default to PNG if no prefix provided
      return `data:image/png;base64,${base64}`;
    }
    return null;
  }, [url, base64]);

  const toggleModal = () => {
    if (!disable && allowExpand && !hasError) {
      setIsModalOpen(!isModalOpen);
    }
  };

  const handleImageLoad = () => {
    setIsLoading(false);
    setHasError(false);
  };

  const handleImageError = () => {
    setIsLoading(false);
    setHasError(true);
  };

  // Reset states when image source changes
  React.useEffect(() => {
    setIsLoading(true);
    setHasError(false);
  }, [imageSrc]);

  const containerStyle = {
    maxWidth: maxWidth || "500px",
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
  };

  const imageStyle = {
    maxWidth: "100%",
    maxHeight: maxHeight || "400px",
    objectFit: "contain",
    cursor: !disable && allowExpand && !hasError ? "pointer" : "default",
    opacity: disable ? 0.5 : 1,
  };

  const renderImage = () => {
    if (hasError) {
      return (
        <div
          className="d-flex flex-column align-items-center justify-content-center text-muted p-3"
          style={{ minHeight: 100 }}
        >
          <MdBrokenImage size={48} />
          <span className="mt-2">Failed to load image</span>
        </div>
      );
    }

    const imageElement = (
      <img
        src={imageSrc}
        alt={title || "Visualizer Image"}
        style={{ ...imageStyle, display: isLoading ? "none" : "block" }}
        onLoad={handleImageLoad}
        onError={handleImageError}
      />
    );

    return (
      <>
        {isLoading && (
          <div
            className="d-flex align-items-center justify-content-center text-muted p-3"
            style={{ minHeight: 100 }}
          >
            <span className="spinner-border spinner-border-sm me-2" />
            Loading...
          </div>
        )}
        {allowExpand && !disable ? (
          <button
            type="button"
            onClick={toggleModal}
            style={{
              border: "none",
              background: "transparent",
              padding: 0,
              cursor: "pointer",
            }}
          >
            {imageElement}
          </button>
        ) : (
          imageElement
        )}
      </>
    );
  };

  if (!imageSrc) {
    return (
      <div className={`${size} text-muted text-center p-3`}>
        No image source provided
      </div>
    );
  }

  return (
    <div id={id} className={`${size} p-2`} style={containerStyle}>
      {title && <div className="fw-bold mb-2 text-center">{title}</div>}
      <div className="position-relative">
        {renderImage()}
        {!hasError && !isLoading && allowExpand && !disable && (
          <>
            <MdZoomIn
              id={`${id}-zoom-icon`}
              size={24}
              className="position-absolute text-white bg-dark bg-opacity-50 rounded p-1"
              style={{ bottom: 8, right: 8, cursor: "pointer" }}
              onClick={toggleModal}
            />
            <UncontrolledTooltip target={`${id}-zoom-icon`} placement="top">
              Click to enlarge
            </UncontrolledTooltip>
          </>
        )}
      </div>
      {description && (
        <div className="text-muted small mt-2 text-center">{description}</div>
      )}

      {/* Modal for expanded view */}
      <Modal isOpen={isModalOpen} toggle={toggleModal} size="xl" centered>
        <ModalHeader toggle={toggleModal}>
          {title || "Image Preview"}
        </ModalHeader>
        <ModalBody className="text-center p-4">
          <img
            src={imageSrc}
            alt={title || "Visualizer Image"}
            style={{
              maxWidth: "100%",
              maxHeight: "80vh",
              objectFit: "contain",
            }}
          />
          {description && <p className="text-muted mt-3 mb-0">{description}</p>}
        </ModalBody>
      </Modal>
    </div>
  );
}

ImageVisualizer.propTypes = {
  id: PropTypes.string.isRequired,
  url: PropTypes.string,
  base64: PropTypes.string,
  title: PropTypes.string,
  description: PropTypes.string,
  maxWidth: PropTypes.oneOfType([PropTypes.number, PropTypes.string]),
  maxHeight: PropTypes.oneOfType([PropTypes.number, PropTypes.string]),
  allowExpand: PropTypes.bool,
  disable: PropTypes.bool,
  size: PropTypes.string,
};

ImageVisualizer.defaultProps = {
  url: "",
  base64: "",
  title: "",
  description: "",
  maxWidth: "500px",
  maxHeight: "400px",
  allowExpand: true,
  disable: false,
  size: "col-auto",
};
