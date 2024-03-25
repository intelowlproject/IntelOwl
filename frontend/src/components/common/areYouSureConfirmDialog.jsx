import React from "react";
import { IoMdWarning } from "react-icons/io";

import { confirm } from "@certego/certego-ui";

export const areYouSureConfirmDialog = (opName) =>
  confirm({
    title: (
      <div className="d-flex-start-center">
        <IoMdWarning className="text-warning" />
        <span className="ms-1">Confirm</span>
      </div>
    ),
    message: (
      <div className="text-wrap">
        <h6 className="text-muted">Operation:</h6>
        <h6 className="text-center text-ul fst-italic">{opName}</h6>
        <hr className="bg-dark" />
        <span className="">Are you sure ?</span>
      </div>
    ),
    confirmColor: "secondary",
    cancelColor: "link text-gray",
  });
