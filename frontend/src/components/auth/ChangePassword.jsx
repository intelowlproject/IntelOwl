import React from "react";
import {
  FormGroup,
  Label,
  Container,
  Input,
  Spinner,
  Button,
} from "reactstrap";
import { Form, Formik } from "formik";
import useTitle from "react-use/lib/useTitle";

import { addToast, ContentSection } from "@certego/certego-ui";

import { useAuthStore } from "../../stores/useAuthStore";

const initialValues = {
  old_password: "",
  new_password: "",
  confirmNewPassword: "",
};

const validateForm = (values) => {
  const errors = {};
  if (!values.old_password) {
    errors.old_password = "Required";
  }
  if (!values.new_password) {
    errors.new_password = "Required";
  }
  if (!values.confirmNewPassword) {
    errors.confirmNewPassword = "Required";
  } else if (values.confirmNewPassword !== values.new_password) {
    errors.confirmNewPassword = "Passwords do not match";
  }
  return errors;
};

// Component
export default function ChangePassword() {
  // page title
  useTitle("IntelOwl | Change Password", { restoreOnUnmount: true });

  // auth store
  const changePassword = useAuthStore(
    React.useCallback((state) => state.service.changePassword, []),
  );

  // callback
  const onSubmit = React.useCallback(
    async (values, { setSubmitting }) => {
      try {
        await changePassword(values);
        addToast("Password changed successfully!", null, "success");
      } catch (error) {
        addToast("Failed to change password", error.parsedMsg, "danger", true);
      } finally {
        setSubmitting(false);
      }
    },
    [changePassword],
  );

  return (
    <ContentSection className="bg-body">
      <Container className="col-12 col-lg-8 col-xl-4 mt-5 mb-5">
        <h3 className="fw-bold">Change Password</h3>
        <hr />
        <Formik
          initialValues={initialValues}
          validate={validateForm}
          onSubmit={onSubmit}
        >
          {(formik) => (
            <Form>
              <FormGroup>
                <Label for="oldPassword">Old Password</Label>
                <Input
                  id="oldPassword"
                  type="password"
                  name="old_password"
                  onChange={formik.handleChange}
                  value={formik.values.oldPassword}
                  invalid={
                    formik.touched.oldPassword && formik.errors.oldPassword
                  }
                />
              </FormGroup>
              <FormGroup>
                <Label for="newPassword">New Password</Label>
                <Input
                  id="newPassword"
                  type="password"
                  name="new_password"
                  onChange={formik.handleChange}
                  value={formik.values.newPassword}
                  invalid={
                    formik.touched.newPassword && formik.errors.newPassword
                  }
                />
              </FormGroup>
              <FormGroup>
                <Label for="confirmNewPassword">Confirm New Password</Label>
                <Input
                  id="confirmNewPassword"
                  type="password"
                  name="confirmNewPassword"
                  onChange={formik.handleChange}
                  value={formik.values.confirmNewPassword}
                  invalid={
                    formik.touched.confirmNewPassword &&
                    formik.errors.confirmNewPassword
                  }
                />
              </FormGroup>
              <FormGroup>
                <Button
                  type="submit"
                  color="primary"
                  disabled={formik.isSubmitting || !formik.isValid}
                >
                  {formik.isSubmitting && <Spinner size="sm" />} Change Password
                </Button>
              </FormGroup>
            </Form>
          )}
        </Formik>
      </Container>
    </ContentSection>
  );
}
