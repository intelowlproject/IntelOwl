// This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
// See the file 'LICENSE' for copying permission.

import React from "react";
import "@testing-library/jest-dom";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { ImageVisualizer } from "../../../../../src/components/common/visualizer/elements/image";

describe("ImageVisualizer component", () => {
  test("renders image from URL", () => {
    render(
      <ImageVisualizer
        id="test-image-1"
        url="https://example.com/image.png"
        title="Test Image"
        description="A test description"
      />,
    );

    expect(screen.getByText("Test Image")).toBeInTheDocument();
    expect(screen.getByText("A test description")).toBeInTheDocument();
    expect(screen.getByAltText("Test Image")).toBeInTheDocument();
  });

  test("renders image from base64", () => {
    const base64Data = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAA";
    render(
      <ImageVisualizer
        id="test-image-2"
        base64={base64Data}
        title="Base64 Image"
      />,
    );

    const img = screen.getByAltText("Base64 Image");
    expect(img).toBeInTheDocument();
    expect(img.src).toContain("data:image/png;base64,");
  });

  test("renders image from base64 with data URI prefix", () => {
    const base64DataUri = "data:image/jpeg;base64,/9j/4AAQSkZJRg==";
    render(
      <ImageVisualizer
        id="test-image-3"
        base64={base64DataUri}
        title="JPEG Image"
      />,
    );

    const img = screen.getByAltText("JPEG Image");
    expect(img.src).toBe(base64DataUri);
  });

  test("shows error message when no source provided", () => {
    render(<ImageVisualizer id="test-image-4" title="No Source" />);

    expect(screen.getByText("No image source provided")).toBeInTheDocument();
  });

  test("renders with disabled state", () => {
    render(
      <ImageVisualizer
        id="test-image-5"
        url="https://example.com/image.png"
        title="Disabled Image"
        disable
      />,
    );

    const img = screen.getByAltText("Disabled Image");
    expect(img).toHaveStyle({ opacity: "0.5" });
  });

  test("opens modal on image click when allowExpand is true", async () => {
    render(
      <ImageVisualizer
        id="test-image-6"
        url="https://example.com/image.png"
        title="Expandable Image"
        allowExpand
      />,
    );

    // Simulate image load
    const img = screen.getByAltText("Expandable Image");
    fireEvent.load(img);

    // Click the button wrapper (image is inside a button when allowExpand is true)
    const button = img.closest("button");
    fireEvent.click(button);

    // Modal should be open - header shows the title
    await waitFor(() => {
      expect(screen.getByRole("dialog")).toBeInTheDocument();
    });
  });

  test("does not open modal when allowExpand is false", () => {
    render(
      <ImageVisualizer
        id="test-image-7"
        url="https://example.com/image.png"
        title="Non-expandable Image"
        allowExpand={false}
      />,
    );

    // Simulate image load
    const img = screen.getByAltText("Non-expandable Image");
    fireEvent.load(img);

    // Click the image
    fireEvent.click(img);

    // Modal should not be open
    expect(screen.queryByText("Image Preview")).not.toBeInTheDocument();
  });

  test("shows loading state initially", () => {
    render(
      <ImageVisualizer
        id="test-image-8"
        url="https://example.com/image.png"
        title="Loading Image"
      />,
    );

    expect(screen.getByText("Loading...")).toBeInTheDocument();
  });

  test("shows error state when image fails to load", async () => {
    render(
      <ImageVisualizer
        id="test-image-9"
        url="https://example.com/broken-image.png"
        title="Broken Image"
      />,
    );

    // Simulate image error
    const img = screen.getByAltText("Broken Image");
    fireEvent.error(img);

    await waitFor(() => {
      expect(screen.getByText("Failed to load image")).toBeInTheDocument();
    });
  });
});
