import React from "react";
import axios from "axios";
import useAxios from "axios-hooks";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import { PluginConfigContainer } from "../../../src/components/plugins/PluginConfigContainer";
import { useOrganizationStore } from "../../../src/stores/useOrganizationStore";
import { API_BASE_URI } from "../../../src/constants/apiURLs";

import {
    mockedUseOrganizationStoreNoOrg,
    mockedUseOrganizationStoreOwner,
    mockedUseOrganizationStoreUser,
} from "../../mock";

jest.mock("axios");
jest.mock("axios-hooks");
jest.mock("../../../src/stores/useOrganizationStore");

describe("test PluginConfigContainer component", () => {
  beforeAll(() => {
    // mock useAxios call
    const configs = {
      user_config: [
        // int - default config
        {
          type: "int",
          description: "Param type: int",
          required: false,
          value: 180,
          is_secret: false,
          attribute: "int_input",
          exist: true,
          default: true,
          id: 10,
          owner: null,
          organization: null
        },
        // bool - user config
        {
          type: "bool",
          description: "Param type: bool",
          required: false,
          value: false,
          is_secret: false,
          attribute: "bool_input",
          exist: true,
          default: false,
          id: 11,
          owner: "user",
          organization: null
        },
        // str - secret required - no config
        {
          type: "str",
          description: "Param type: str",
          required: true,
          value: null,
          is_secret: true,
          attribute: "str_input",
          exist: false,
          default: false
        },
        // float - default config
        {
          type: "float",
          description: "Param type: float",
          required: false,
          value: 10.5,
          is_secret: false,
          attribute: "float_input",
          exist: true,
          default: true,
          owner: null,
          organization: null
        },
        // list - default config
        {
          type: "list",
          description: "Param type: list",
          required: true,
          value: '["list value 1", "list value 2"]',
          is_secret: true,
          attribute: "list_input",
          exist: true,
          default: true,
          owner: null,
          organization: null
        },
        // dict - no config
        {
          type: "dict",
          description: "Param type: dict",
          required: true,
          value: null,
          is_secret: true,
          attribute: "dict_input",
          exist: false,
          default: false
        },
      ], 
      organization_config: [
        // int - default config
        {
          type: "int",
          description: "Param type: int",
          required: false,
          value: 180,
          is_secret: false,
          attribute: "int_input",
          exist: true,
          default: true,
          id: 10,
          owner: null,
          organization: null
        },
        // bool - default config
        {
          type: "bool",
          description: "Param type: bool",
          required: false,
          value: true,
          is_secret: false,
          attribute: "bool_input",
          exist: true,
          default: true,
          id: 11,
          owner: null,
          organization: null
        },
        // str - secret required - no config
        {
          type: "str",
          description: "Param type: str",
          required: true,
          value: null,
          is_secret: true,
          attribute: "str_input",
          exist: false,
          default: false
        },
        // float - default config
        {
          type: "float",
          description: "Param type: float",
          required: false,
          value: 10.5,
          is_secret: false,
          attribute: "float_input",
          exist: true,
          default: true,
          owner: null,
          organization: null
        },
        // list - default config
        {
          type: "list",
          description: "Param type: list",
          required: true,
          value: '["list value 1", "list value 2"]',
          is_secret: true,
          attribute: "list_input",
          exist: true,
          default: true,
          owner: null,
          organization: null
        },
        // dict - no config
        {
          type: "dict",
          description: "Param type: dict",
          required: true,
          value: null,
          is_secret: true,
          attribute: "dict_input",
          exist: false,
          default: false
        },
      ]
    };
    const loadingConfigs = false;
    const errorConfigs = null;
    const refetchPluginConfig = () => jest.fn();
    useAxios.mockImplementation(() => [
      { data: configs, loading: loadingConfigs, error: errorConfigs }, refetchPluginConfig
    ]);
  });

  test("plugins config modal - no org", async () => {
    const user = userEvent.setup();
    useOrganizationStore.mockImplementation(
        jest.fn((state) => state(mockedUseOrganizationStoreNoOrg)),
    );

    const {container} = render(
      <BrowserRouter>
        <PluginConfigContainer
          pluginName="AbuseIPDB"
          pluginType="analyzer"
        />
      </BrowserRouter>,
    );

    // router tabs
    const routerTabs = screen.getByRole("list");
    expect(routerTabs).toBeInTheDocument();
    expect(routerTabs.className).toContain("nav-tabs");
    // nav items
    const userConfigButton = screen.getByText("User config");
    expect(userConfigButton).toBeInTheDocument();
    expect(userConfigButton.closest("a").className).toContain("active"); // selected
    const orgConfigButton = screen.queryByTestId("orgconfig__AbuseIPDB");
    expect(orgConfigButton).not.toBeInTheDocument(); // no org tab

    // USER CONFIG

    // int - default config
    expect(screen.getAllByText("int_input")[0]).toBeInTheDocument(); 
    const inputValue = container.querySelector("#pluginConfig_userConfig-int_input");
    expect(inputValue).toBeInTheDocument();
    expect(inputValue).toHaveValue(180);
    const firstClearButton = container.querySelector("#pluginConfig_userConfig-int_input-deletebtn");
    expect(firstClearButton).toBeInTheDocument();
    expect(firstClearButton.className).toContain("disabled");
    // bool - user config
    expect(screen.getAllByText("bool_input")[0]).toBeInTheDocument();
    const trueValue = screen.getAllByRole("radio", { name: "true" })[0];
    expect(trueValue).toBeInTheDocument();
    expect(trueValue).not.toBeChecked();
    const falseValue = screen.getAllByRole("radio", { name: "false" })[0];
    expect(falseValue).toBeInTheDocument();
    expect(falseValue).toBeChecked();
    const secondClearButton = container.querySelector("#pluginConfig_userConfig-bool_input-deletebtn");
    expect(secondClearButton).toBeInTheDocument();
    expect(secondClearButton.className).not.toContain("disabled");
    // str - secret required - no config
    const strLabel = screen.getAllByText("str_input")[1];
    expect(strLabel).toBeInTheDocument();
    expect(strLabel.className).toContain("required");
    const strValue = container.querySelector("#pluginConfig_userConfig-str_input");
    expect(strValue).toBeInTheDocument();
    const thirdClearButton = container.querySelector("#pluginConfig_userConfig-str_input-deletebtn");
    expect(thirdClearButton).toBeInTheDocument();
    expect(thirdClearButton.className).toContain("disabled");
    // float - default config
    const floatValue = container.querySelector("#pluginConfig_userConfig-float_input");
    expect(floatValue).toBeInTheDocument();
    expect(floatValue).toHaveValue(10.5);
    const fourthClearButton = container.querySelector("#pluginConfig_userConfig-float_input-deletebtn");
    expect(fourthClearButton).toBeInTheDocument();
    expect(fourthClearButton.className).toContain("disabled");
    // list - default config
    const listContainer = container.querySelector("#pluginConfig_userConfig-list_input");
    expect(listContainer).toBeInTheDocument();
    const listValue1 = container.querySelector("#userConfig__value-0");
    expect(listValue1).toBeInTheDocument(); 
    expect(listValue1).toHaveValue("list value 1");
    expect(container.querySelector("#userConfig__value-0-deletebtn")).toBeInTheDocument(); 
    const listValue2 = container.querySelector("#userConfig__value-1");
    expect(listValue2).toBeInTheDocument(); 
    expect(listValue2).toHaveValue("list value 2");
    expect(container.querySelector("#userConfig__value-1-deletebtn")).toBeInTheDocument(); 
    const fifthClearButton = container.querySelector("#pluginConfig_userConfig-list_input-deletebtn");
    expect(fifthClearButton).toBeInTheDocument();
    expect(fifthClearButton.className).toContain("disabled");
    // dict - secret required - no config
    const dictInput = screen.getAllByText("dict_input")[0];
    expect(dictInput).toBeInTheDocument();
    const sixthClearButton = container.querySelector("#pluginConfig_userConfig-dict_input-deletebtn");
    expect(sixthClearButton).toBeInTheDocument();
    expect(sixthClearButton.className).toContain("disabled");

    const saveButton = screen.getAllByRole("button", { name: "Save" })[0];
    expect(saveButton).toBeInTheDocument();

    await user.click(trueValue); // update default config
    await user.type(strValue, "myNewSecret"); // create new config
    await user.click(saveButton);

    await waitFor(() => {
      expect(axios.patch).toHaveBeenCalledWith(`${API_BASE_URI}/plugin-config/AbuseIPDB/analyzer`, [ 
        {
          attribute: "bool_input",
          value: "\"true\"",
        }
      ]);
      expect(axios.post).toHaveBeenCalledWith(`${API_BASE_URI}/plugin-config/AbuseIPDB/analyzer`, [
        {
          attribute: "str_input",
          value: "\"myNewSecret\"",
        }
      ]);
    });
  });

  test("plugins config modal - org owner", async () => {
    const user = userEvent.setup();
    useOrganizationStore.mockImplementation(
        jest.fn((state) => state(mockedUseOrganizationStoreOwner)),
    );

    const {container} = render(
      <BrowserRouter>
        <PluginConfigContainer
            pluginName="AbuseIPDB"
            pluginType="analyzer"
        />
      </BrowserRouter>,
    );

    // router tabs
    const routerTabs = screen.getByRole("list");
    expect(routerTabs).toBeInTheDocument();
    expect(routerTabs.className).toContain("nav-tabs");
    // nav items
    const userConfigButton = screen.getByText("User config");
    expect(userConfigButton).toBeInTheDocument();
    expect(userConfigButton.closest("a").className).toContain("active"); // selected
    const orgConfigButton = screen.getByText("Org config");;
    expect(orgConfigButton).toBeInTheDocument();
    expect(orgConfigButton.closest("a").className).not.toContain("active"); // not selected

    // select org tab
    await user.click(orgConfigButton);
    await waitFor(() => {
      expect(userConfigButton.closest("a").className).not.toContain("active"); // not selected
      expect(orgConfigButton.closest("a").className).toContain("active"); // selected

      // ORG CONFIG
      // int - default config
      expect(screen.getAllByText("int_input")[1]).toBeInTheDocument(); 
      const inputValue = container.querySelector("#pluginConfig_orgConfig-int_input");
      expect(inputValue).toBeInTheDocument();
      expect(inputValue).toHaveValue(180);
      const firstClearButton = container.querySelector("#pluginConfig_orgConfig-int_input-deletebtn");
      expect(firstClearButton).toBeInTheDocument();
      expect(firstClearButton.className).toContain("disabled");
      // bool - default config
      expect(screen.getAllByText("bool_input")[1]).toBeInTheDocument();
      const trueValue = screen.getAllByRole("radio", { name: "true" })[1];
      expect(trueValue).toBeInTheDocument();
      expect(trueValue).toBeChecked();
      const falseValue = screen.getAllByRole("radio", { name: "false" })[1];
      expect(falseValue).toBeInTheDocument();
      expect(falseValue).not.toBeChecked();
      const secondClearButton = container.querySelector("#pluginConfig_orgConfig-bool_input-deletebtn");
      expect(secondClearButton).toBeInTheDocument();
      expect(secondClearButton.className).toContain("disabled");
      // str - secret required - no config
      const strLabel = screen.getAllByText("str_input")[1];
      expect(strLabel).toBeInTheDocument();
      expect(strLabel.className).toContain("required");
      const strValue = container.querySelector("#pluginConfig_orgConfig-str_input");
      expect(strValue).toBeInTheDocument();
      const thirdClearButton = container.querySelector("#pluginConfig_orgConfig-str_input-deletebtn");
      expect(thirdClearButton).toBeInTheDocument();
      expect(thirdClearButton.className).toContain("disabled");
      // float - default config
      const floatValue = container.querySelector("#pluginConfig_orgConfig-float_input");
      expect(floatValue).toBeInTheDocument();
      expect(floatValue).toHaveValue(10.5);
      const fourthClearButton = container.querySelector("#pluginConfig_orgConfig-float_input-deletebtn");
      expect(fourthClearButton).toBeInTheDocument();
      expect(fourthClearButton.className).toContain("disabled");
      // list - default config
      const listContainer = container.querySelector("#pluginConfig_orgConfig-list_input");
      expect(listContainer).toBeInTheDocument();
      const listValue1 = container.querySelector("#orgConfig__value-0");
      expect(listValue1).toBeInTheDocument(); 
      expect(listValue1).toHaveValue("list value 1");
      expect(container.querySelector("#orgConfig__value-0-deletebtn")).toBeInTheDocument(); 
      const listValue2 = container.querySelector("#orgConfig__value-1");
      expect(listValue2).toBeInTheDocument(); 
      expect(listValue2).toHaveValue("list value 2");
      expect(container.querySelector("#orgConfig__value-1-deletebtn")).toBeInTheDocument(); 
      const fifthClearButton = container.querySelector("#pluginConfig_orgConfig-list_input-deletebtn");
      expect(fifthClearButton).toBeInTheDocument();
      expect(fifthClearButton.className).toContain("disabled");
      // dict - secret required - no config
      const dictInput = screen.getAllByText("dict_input")[1];
      expect(dictInput).toBeInTheDocument();
      const sixthClearButton = container.querySelector("#pluginConfig_orgConfig-dict_input-deletebtn");
      expect(sixthClearButton).toBeInTheDocument();
      expect(sixthClearButton.className).toContain("disabled");

      const saveButtonOrg = screen.getAllByRole("button", { name: "Save" })[1];
      expect(saveButtonOrg).toBeInTheDocument();
    
      user.click(trueValue); // update default config
      user.type(strValue, "myNewSecret"); // create new config
      user.click(saveButtonOrg);

      waitFor(() => {
        expect(axios.patch).toHaveBeenCalledWith(`${API_BASE_URI}/plugin-config/AbuseIPDB/analyzer`, [ 
          {
            attribute: "bool_input",
            value: "\"true\"",
            organization: "test_org",
          }
        ]);
        expect(axios.post).toHaveBeenCalledWith(`${API_BASE_URI}/plugin-config/AbuseIPDB/analyzer`, [
          {
            attribute: "str_input",
            value: "\"myNewSecret\"",
            organization: "test_org",
          }
        ]);
      });
    });
  });

  test("plugins config modal - org user", async () => {
    const user = userEvent.setup();
    useOrganizationStore.mockImplementation(
        jest.fn((state) => state(mockedUseOrganizationStoreUser)),
    );

    const {container} = render(
      <BrowserRouter>
        <PluginConfigContainer
            pluginName="AbuseIPDB"
            pluginType="analyzer"
        />
      </BrowserRouter>,
    );

    // router tabs
    const routerTabs = screen.getByRole("list");
    expect(routerTabs).toBeInTheDocument();
    expect(routerTabs.className).toContain("nav-tabs");
    // nav items
    const userConfigButton = screen.getByText("User config");
    expect(userConfigButton).toBeInTheDocument();
    expect(userConfigButton.closest("a").className).toContain("active"); // selected
    const orgConfigButton = screen.getByText("Org config");;
    expect(orgConfigButton).toBeInTheDocument();
    expect(orgConfigButton.closest("a").className).not.toContain("active"); // not selected

    // select org tab
    await user.click(orgConfigButton);
    await waitFor(() => {
      expect(userConfigButton.closest("a").className).not.toContain("active"); // not selected
      expect(orgConfigButton.closest("a").className).toContain("active"); // selected

      // ORG CONFIG
      // int - default config
      expect(screen.getAllByText("int_input")[1]).toBeInTheDocument(); 
      const inputValue = container.querySelector("#pluginConfig_orgConfig-int_input");
      expect(inputValue).toBeInTheDocument();
      expect(inputValue).toHaveValue(180);
      expect(inputValue.className).toContain("disabled");
      const firstClearButton = container.querySelector("#pluginConfig_orgConfig-int_input-deletebtn");
      expect(firstClearButton).toBeInTheDocument();
      expect(firstClearButton.className).toContain("disabled");
      // bool - default config
      expect(screen.getAllByText("bool_input")[1]).toBeInTheDocument();
      const trueValue = screen.getAllByRole("radio", { name: "true" })[1];
      expect(trueValue).toBeInTheDocument();
      expect(trueValue).toBeChecked();
      const falseValue = screen.getAllByRole("radio", { name: "false" })[1];
      expect(falseValue).toBeInTheDocument();
      expect(falseValue).not.toBeChecked();
      const secondClearButton = container.querySelector("#pluginConfig_orgConfig-bool_input-deletebtn");
      expect(secondClearButton).toBeInTheDocument();
      expect(secondClearButton.className).toContain("disabled");
      // str - secret required - no config
      const strLabel = screen.getAllByText("str_input")[1];
      expect(strLabel).toBeInTheDocument();
      expect(strLabel.className).toContain("required");
      const strValue = container.querySelector("#pluginConfig_orgConfig-str_input");
      expect(strValue).toBeInTheDocument();
      expect(strValue.className).toContain("disabled");
      const thirdClearButton = container.querySelector("#pluginConfig_orgConfig-str_input-deletebtn");
      expect(thirdClearButton).toBeInTheDocument();
      expect(thirdClearButton.className).toContain("disabled");
      // float - default config
      const floatValue = container.querySelector("#pluginConfig_orgConfig-float_input");
      expect(floatValue).toBeInTheDocument();
      expect(floatValue).toHaveValue(10.5);
      expect(floatValue.className).toContain("disabled");
      const fourthClearButton = container.querySelector("#pluginConfig_orgConfig-float_input-deletebtn");
      expect(fourthClearButton).toBeInTheDocument();
      expect(fourthClearButton.className).toContain("disabled");
      // list - default config
      const listContainer = container.querySelector("#pluginConfig_orgConfig-list_input");
      expect(listContainer).toBeInTheDocument();
      const listValue1 = container.querySelector("#orgConfig__value-0");
      expect(listValue1).toBeInTheDocument(); 
      expect(listValue1).toHaveValue("list value 1");
      expect(listValue1.className).toContain("disabled");
      expect(container.querySelector("#orgConfig__value-0-deletebtn")).toBeInTheDocument(); 
      const listValue2 = container.querySelector("#orgConfig__value-1");
      expect(listValue2).toBeInTheDocument(); 
      expect(listValue2).toHaveValue("list value 2");
      expect(listValue2.className).toContain("disabled");
      expect(container.querySelector("#orgConfig__value-1-deletebtn")).toBeInTheDocument(); 
      const fifthClearButton = container.querySelector("#pluginConfig_orgConfig-list_input-deletebtn");
      expect(fifthClearButton).toBeInTheDocument();
      expect(fifthClearButton.className).toContain("disabled");
      // dict - secret required - no config
      const dictInput = screen.getAllByText("dict_input")[0];
      expect(dictInput).toBeInTheDocument();
      const sixthClearButton = container.querySelector("#pluginConfig_orgConfig-dict_input-deletebtn");
      expect(sixthClearButton).toBeInTheDocument();
      expect(sixthClearButton.className).toContain("disabled");

      const saveButtonOrg = screen.getAllByRole("button", { name: "Save" })[1];
      expect(saveButtonOrg).toBeInTheDocument();
  });
  });

  test("plugins config modal - delete config", async () => {
    const user = userEvent.setup();
    useOrganizationStore.mockImplementation(
        jest.fn((state) => state(mockedUseOrganizationStoreNoOrg)),
    );

    const {container} = render(
      <BrowserRouter>
        <PluginConfigContainer
          pluginName="AbuseIPDB"
          pluginType="analyzer"
        />
      </BrowserRouter>,
    );

    // router tabs
    const routerTabs = screen.getByRole("list");
    expect(routerTabs).toBeInTheDocument();
    expect(routerTabs.className).toContain("nav-tabs");
    // nav items
    const userConfigButton = screen.getByText("User config");
    expect(userConfigButton).toBeInTheDocument();
    expect(userConfigButton.closest("a").className).toContain("active"); // selected
    const orgConfigButton = screen.queryByTestId("orgconfig__AbuseIPDB");
    expect(orgConfigButton).not.toBeInTheDocument(); // no org tab

    // user config
    // int - default config
    expect(screen.getAllByText("int_input")[0]).toBeInTheDocument(); 
    const inputValue = container.querySelector("#pluginConfig_userConfig-int_input");
    expect(inputValue).toBeInTheDocument();
    expect(inputValue).toHaveValue(180);
    const firstClearButton = container.querySelector("#pluginConfig_userConfig-int_input-deletebtn");
    expect(firstClearButton).toBeInTheDocument();
    expect(firstClearButton.className).toContain("disabled");
    // bool - user config
    expect(screen.getAllByText("bool_input")[0]).toBeInTheDocument();
    const trueValue = screen.getAllByRole("radio", { name: "true" })[0];
    expect(trueValue).toBeInTheDocument();
    expect(trueValue).not.toBeChecked();
    const falseValue = screen.getAllByRole("radio", { name: "false" })[0];
    expect(falseValue).toBeInTheDocument();
    expect(falseValue).toBeChecked();
    const secondClearButton = container.querySelector("#pluginConfig_userConfig-bool_input-deletebtn");
    expect(secondClearButton).toBeInTheDocument();
    expect(secondClearButton.className).not.toContain("disabled");

    const saveButton = screen.getAllByRole("button", { name: "Save" })[0];
    expect(saveButton).toBeInTheDocument();

    await user.click(secondClearButton); // delete config
    await waitFor(() => {
      expect(axios.delete).toHaveBeenCalledWith(`${API_BASE_URI}/plugin-config/11`);
    });
  });
});
