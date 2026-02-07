import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { TLPTag } from "../../../src/components/common/TLPTag";

describe("TLPTag component", () => {
  test("CLEAR TLP renders with correct background and text color", () => {
    const { container } = render(<TLPTag value="CLEAR" />);
    
    const badge = container.querySelector('[id^="tlptag-badge__CLEAR"]');
    expect(badge).toBeInTheDocument();
    expect(badge).toHaveTextContent("CLEAR");
    
    // CLEAR should have white background (#ffffff) and black text
    expect(badge).toHaveStyle({
      backgroundColor: "#ffffff",
      color: "#000000",
    });
  });

  test("RED TLP renders with correct background and text color", () => {
    const { container } = render(<TLPTag value="RED" />);
    
    const badge = container.querySelector('[id^="tlptag-badge__RED"]');
    expect(badge).toBeInTheDocument();
    expect(badge).toHaveTextContent("RED");
    
    // RED should have red background (#ff0033) and white text
    expect(badge).toHaveStyle({
      backgroundColor: "#ff0033",
      color: "#FFFFFF",
    });
  });

  test("GREEN TLP renders with correct background and text color", () => {
    const { container } = render(<TLPTag value="GREEN" />);
    
    const badge = container.querySelector('[id^="tlptag-badge__GREEN"]');
    expect(badge).toBeInTheDocument();
    expect(badge).toHaveTextContent("GREEN");
    
    // GREEN should have green background (#33ff00) and black text
    expect(badge).toHaveStyle({
      backgroundColor: "#33ff00",
      color: "#000000",
    });
  });

  test("AMBER TLP renders with correct background and text color", () => {
    const { container } = render(<TLPTag value="AMBER" />);
    
    const badge = container.querySelector('[id^="tlptag-badge__AMBER"]');
    expect(badge).toBeInTheDocument();
    expect(badge).toHaveTextContent("AMBER");
    
    // AMBER should have amber background (#ffc000) and black text
    expect(badge).toHaveStyle({
      backgroundColor: "#ffc000",
      color: "#000000",
    });
  });

  test("Multiple TLPTag instances with same value have unique IDs", () => {
    const { container } = render(
      <>
        <TLPTag value="RED" />
        <TLPTag value="RED" />
      </>,
    );
    
    const badges = container.querySelectorAll('[id^="tlptag-badge__RED"]');
    expect(badges).toHaveLength(2);
    
    // Ensure each badge has a unique ID
    const id1 = badges[0].getAttribute("id");
    const id2 = badges[1].getAttribute("id");
    expect(id1).not.toEqual(id2);
  });


});
