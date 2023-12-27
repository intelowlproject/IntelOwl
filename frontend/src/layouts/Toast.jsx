import React from "react";
import { useToastr, Toaster } from "@certego/certego-ui";

function Toast() {
  // consume store
  const toasts = useToastr((state) => state.toasts);
  console.debug("Toasts:", toasts);

  return (
    <section className="fixed-bottom" id="app-toasts">
      {toasts.map((tProps) => (
        <Toaster key={tProps.id} {...tProps} />
      ))}
    </section>
  );
}

export default Toast;
