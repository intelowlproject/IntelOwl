import React from "react";

export function prettifyErrors(errorResponse) {
  // only validation errors returns an array of errors
  /**
      "errors":{
              "detail":[
                  {"observable_name":["This field may not be blank.", "another error"]},
                  {"another_key": "another error"},
              ]
          }
     */
  if (Array.isArray(errorResponse.response.data?.errors?.detail)) {
    let prettyHTMLList = [];
    errorResponse.response.data.errors.detail.forEach((objectDict) => {
      Object.values(objectDict).forEach((errorItem) => {
        if (Array.isArray(errorItem)) {
          errorItem.forEach((error) => prettyHTMLList.push(error));
        } else {
          prettyHTMLList.push(errorItem);
        }
      });
    });
    prettyHTMLList = prettyHTMLList.map((error) => <li>{error}</li>);
    return <ul>{prettyHTMLList}</ul>;
  }

  return JSON.stringify(errorResponse.response.data);
}
