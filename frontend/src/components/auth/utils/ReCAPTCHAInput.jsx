import React from "react";
import ReCAPTCHA from "react-google-recaptcha";
import usePrevious from "react-use/lib/usePrevious";
import { useFormikContext } from "formik";

import { RECAPTCHA_SITEKEY } from "../../../constants/environment";

export default function ReCAPTCHAInput(props) {
  const { isSubmitting, setFieldValue } = useFormikContext();

  // refs
  const recaptchaRef = React.useRef();

  // callbacks
  const onChange = React.useCallback(
    (value) => setFieldValue("recaptcha", value),
    [setFieldValue]
  );

  // side-effect
  const prevIsSubmitting = usePrevious(isSubmitting);

  React.useEffect(() => {
    const wasSubmitted = prevIsSubmitting === true && isSubmitting === false;
    if (wasSubmitted) {
      recaptchaRef.current.reset();
      setFieldValue("recaptcha", null);
    }
  }, [recaptchaRef, setFieldValue, prevIsSubmitting, isSubmitting]);

  return (
    <ReCAPTCHA
      ref={recaptchaRef}
      sitekey={RECAPTCHA_SITEKEY}
      onChange={onChange}
      {...props}
    />
  );
}
