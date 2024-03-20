import React from "react";

const { prettifyErrors } = require("../../src/utils/api");

describe("prettify errors", () => {
  test("error in response data", () => {
    const error = {
      message: "Request failed with status code 405",
      name: "AxiosError",
      code: "ERR_BAD_REQUEST",
      config: {},
      request: {},
      response: {
        data: {
          detail: 'Method "POST" not allowed.',
        },
      },
    };
    expect(prettifyErrors(error)).toEqual('Method "POST" not allowed.');
  });
  test("single validation error", () => {
    const error = {
      message: "Request failed with status code 400",
      name: "AxiosError",
      code: "ERR_BAD_REQUEST",
      config: {},
      request: {},
      response: {
        data: {
          errors: {
            detail: "No healthcheck implemented",
          },
        },
      },
    };
    expect(prettifyErrors(error)).toEqual("No healthcheck implemented");
  });
  test("multiple validation error", () => {
    const error = {
      message: "Request failed with status code 400",
      name: "AxiosError",
      code: "ERR_BAD_REQUEST",
      config: {},
      request: {},
      response: {
        data: {
          errors: {
            detail: [
              {
                observable_name: [
                  "This field may not be blank.",
                  "another error",
                ],
              },
              { another_key: "another error" },
            ],
          },
        },
      },
    };
    expect(prettifyErrors(error)).toEqual(
      <ul>
        <li>This field may not be blank.</li>
        <li>another error</li>
        <li>another error</li>
      </ul>,
    );
  });
  test("model validation error", () => {
    const error = {
      message: "Request failed with status code 400",
      name: "AxiosError",
      code: "ERR_BAD_REQUEST",
      config: {},
      request: {},
      response: {
        data: {
          errors: {
            test_key: ["error"],
            name: ["This field is required.", "another error"],
          },
        },
      },
    };
    expect(prettifyErrors(error)).toEqual(
      <ul>
        <strong>test_key</strong>
        <li>error</li>
        <strong>name</strong>
        <li>This field is required.</li>
        <li>another error</li>
      </ul>,
    );
  });
});
