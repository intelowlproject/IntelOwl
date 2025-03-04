import React from "react";
import "@testing-library/jest-dom";
import { render } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";

import { JsonEditor } from "../../../src/components/common/JsonEditor";

describe("test JsonEditor component", () => {
  const jsonData = {
    first_key: "value",
    second_key: 123,
  };

  test("JsonEditor read only", async () => {
    const { container } = render(
      <BrowserRouter>
        <JsonEditor id="test" initialJsonData={jsonData} readOnly />
      </BrowserRouter>,
    );

    const jsonEditor = container.querySelector("#jsonAceEditor__test");
    expect(jsonEditor).toBeInTheDocument();
    const jsonEditorInput = container.querySelector(".ace_text-input");
    expect(jsonEditorInput).toBeInTheDocument();
    expect(jsonEditorInput.hasAttribute("readonly")).toBe(true);
  });

  test("JsonEditor editable", async () => {
    const onChangeFn = jest.fn().mockImplementation((value) => value);
    const { container } = render(
      <BrowserRouter>
        <JsonEditor
          id="test"
          initialJsonData={jsonData}
          onChange={onChangeFn}
        />
      </BrowserRouter>,
    );

    const jsonEditor = container.querySelector("#jsonAceEditor__test");
    expect(jsonEditor).toBeInTheDocument();
    const jsonEditorInput = container.querySelector(".ace_text-input");
    expect(jsonEditorInput).toBeInTheDocument();
    expect(jsonEditorInput.hasAttribute("readonly")).toBe(false);
  });
});
