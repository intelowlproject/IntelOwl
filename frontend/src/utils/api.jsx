import React from "react";

export function prettifyErrors(errorResponse) {
  // multiple validation errors
  // only validation errors returns an array of errors
  /**
    "errors":{
      "detail":[
          "this is an error",
          {"observable_name":["This field may not be blank.", "another error"]},
          {"another_key": "another error"},
      ]
    }
  */
  if (Array.isArray(errorResponse.response?.data?.errors?.detail)) {
    let prettyHTMLList = [];
    errorResponse.response.data.errors.detail.forEach((errorElement) => {
      if (typeof errorElement === "object") {
        Object.values(errorElement).forEach((errorItem) => {
          if (Array.isArray(errorItem)) {
            errorItem.forEach((error) => prettyHTMLList.push(error));
          } else {
            prettyHTMLList.push(errorItem);
          }
        });
      } else {
        prettyHTMLList.push(errorElement);
      }
    });
    prettyHTMLList = prettyHTMLList.map((error) => <li>{error}</li>);
    return <ul>{prettyHTMLList}</ul>;
  }
  // single validation error
  /**
    "errors":{
      "detail": "Not implemented",
    }
  */
  if (errorResponse.response?.data?.errors?.detail) {
    return errorResponse.response.data.errors.detail;
  }
  // error directly in response data
  /**
    "data":{
      "detail": "Method "POST" not allowed.",
    }
  */
  if (errorResponse.response?.data?.detail) {
    return errorResponse.response.data.detail;
  }
  // model validation errors
  /**
    "errors":{
      "test_key": ["error"],
      "another_key": ["error", "another error"],
    }
  */
  if (Object.keys(errorResponse.response.data?.errors).length > 0) {
    const prettyHTMLList = [];
    Object.entries(errorResponse.response.data?.errors).forEach(
      ([errorField, errorItem]) => {
        prettyHTMLList.push(<strong>{errorField}</strong>);
        if (Array.isArray(errorItem)) {
          errorItem.forEach((error) => prettyHTMLList.push(<li>{error}</li>));
        } else {
          prettyHTMLList.push(<li>{errorItem}</li>);
        }
      },
    );
    return <ul>{prettyHTMLList}</ul>;
  }

  // other types of errors
  /**
    "errors": [
        {
          "detail": [
              "You are not owner or admin of the organization"
          ]
        }
    ]
  */
  /**
   "errors": [
        "Config with this parameters already exists"
    ]
  */
  return JSON.stringify(errorResponse.response?.data);
}
