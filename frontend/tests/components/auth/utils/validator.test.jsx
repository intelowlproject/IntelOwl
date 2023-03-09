import {
  ComparePassword,
  PasswordValidator,
  UserFieldsValidator,
  UsernameValidator,
  ProfileValidator,
  EmailValidator,
  RecaptchaValidator,
} from "../../../../src/components/auth/utils/validator";
import { HACKER_MEME_STRING } from "../../../../src/constants";

jest.mock("../../../../src/constants/environment", () => ({
  RECAPTCHA_SITEKEY: "key",
}));

describe("Compare Password", () => {
  test("Password do match", () => {
    const password = "intelowlpassword";
    const confirmPassword = "intelowlpassword";
    expect(ComparePassword(password, confirmPassword)).toEqual({});
  });
  test("Password do not match", () => {
    const password = "intelowlpassword";
    const confirmPassword = "IntelowlPassword";
    expect(ComparePassword(password, confirmPassword)).toEqual({
      password: "Passwords do not match.",
      confirmPassword: "Passwords do not match.",
    });
  });
});

describe("Password", () => {
  test("Valid password", () => {
    const password = "intelowlpassword";
    expect(PasswordValidator(password)).toEqual({});
  });
  test("Required password", () => {
    const password = "";
    expect(PasswordValidator(password)).toEqual({ password: "Required" });
  });
  test("Too short password", () => {
    const password = "test";
    expect(PasswordValidator(password)).toEqual({
      password: "Must be 12 characters or more",
    });
  });
  test("Invalid password", () => {
    const numericPassword = "123456123456";
    expect(PasswordValidator(numericPassword)).toEqual({
      password:
        "The password is entirely numeric or contains special characters",
    });
    const password = "intelowlpassword$";
    expect(PasswordValidator(password)).toEqual({
      password:
        "The password is entirely numeric or contains special characters",
    });
  });
});

describe("User fields", () => {
  test("Valid user fields", () => {
    expect(UserFieldsValidator("first_name", "test")).toEqual({});
    expect(UserFieldsValidator("last_name", "test")).toEqual({});
  });
  test("Required user fields", () => {
    expect(UserFieldsValidator("first_name", "")).toEqual({
      first_name: "Required",
    });
    expect(UserFieldsValidator("last_name", "")).toEqual({
      last_name: "Required",
    });
  });
  test("Too short user field", () => {
    expect(UserFieldsValidator("first_name", "t")).toEqual({
      first_name: "Must be 4 characters or more",
    });
    expect(UserFieldsValidator("last_name", "t")).toEqual({
      last_name: "Must be 4 characters or more",
    });
  });
  test("Too long user field", () => {
    expect(UserFieldsValidator("first_name", "first_nametoolong")).toEqual({
      first_name: "Must be 15 characters or less",
    });
    expect(UserFieldsValidator("last_name", "last_nametoolong")).toEqual({
      last_name: "Must be 15 characters or less",
    });
  });
});

describe("Username", () => {
  test("Valid username", () => {
    const username = "test";
    expect(UsernameValidator(username)).toEqual({});
  });
  test("Invalid username", () => {
    const username = "admin";
    expect(UsernameValidator(username)).toEqual({
      username: HACKER_MEME_STRING,
    });
  });
});

describe("Profile fields", () => {
  test("Valid profile", () => {
    expect(ProfileValidator("company_name", "company")).toEqual({});
    expect(ProfileValidator("company_role", "company")).toEqual({});
  });
  test("Required profile", () => {
    expect(ProfileValidator("company_name", "")).toEqual({
      company_name: "Required",
    });
    expect(ProfileValidator("company_role", "")).toEqual({
      company_role: "Required",
    });
  });
  test("Too short profile", () => {
    expect(ProfileValidator("company_name", "c")).toEqual({
      company_name: "Must be 3 characters or more",
    });
    expect(ProfileValidator("company_role", "c")).toEqual({
      company_role: "Must be 3 characters or more",
    });
  });
  test("Too long profile", () => {
    expect(
      ProfileValidator("company_name", "company_nametoolongcompany_nametoolong")
    ).toEqual({ company_name: "Must be 30 characters or less" });
    expect(
      ProfileValidator("company_role", "company_roletoolongcompany_roletoolong")
    ).toEqual({ company_role: "Must be 30 characters or less" });
  });
});

describe("Email", () => {
  test("Valid email", () => {
    const email = "test@test.com";
    expect(EmailValidator(email)).toEqual({});
  });
  test("Required email", () => {
    const email = "";
    expect(EmailValidator(email)).toEqual({ email: "Required" });
  });
  test("Invalid email", () => {
    const email = "test@test";
    expect(EmailValidator(email)).toEqual({ email: "Invalid email address" });
  });
});

describe("Recaptcha", () => {
  test("Recaptcha", () => {
    const recaptcha = "";
    expect(RecaptchaValidator(recaptcha)).toEqual({});
  });
  test("Required recaptcha", () => {
    const recaptcha = "noKey";
    expect(RecaptchaValidator(recaptcha)).toEqual({ recaptcha: "Required" });
  });
});
