import React from "react";
import { Spinner } from "reactstrap";

// we can't delete this function because IconButton expects Icon as a function
export function SpinnerIcon() {
  return <Spinner type="border" size="sm" className="text-darker" />;
}
