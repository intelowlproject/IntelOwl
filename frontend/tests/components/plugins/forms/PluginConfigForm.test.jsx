import React from "react";
import axios from "axios";
import "@testing-library/jest-dom";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import { PluginConfigForm } from "../../../../src/components/plugins/forms/PluginConfigForm";
import { useOrganizationStore } from "../../../../src/stores/useOrganizationStore";
import { API_BASE_URI } from "../../../../src/constants/apiURLs";
import { PluginConfigTypes } from "../../../../src/constants/pluginConst";

import {
  mockedUseOrganizationStoreNoOrg,
  mockedUseOrganizationStoreOwner,
  mockedUseOrganizationStoreUser,
  mockedUsePluginConfigurationStore,
} from "../../../mock";

jest.mock("axios");
jest.mock("../../../../src/stores/useOrganizationStore");

jest.mock("../../../../src/stores/usePluginConfigurationStore", () => ({
  usePluginConfigurationStore: jest.fn((state) =>
    state(mockedUsePluginConfigurationStore),
  ),
}));

describe("test PluginConfigForm component", () => {
  let configs;
  beforeEach(() => {
    configs = {
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
          id: 10,
          owner: null,
          organization: null,
          parameter: 10,
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
          id: 11,
          owner: "user",
          organization: null,
          parameter: 11,
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
          parameter: 12,
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
          owner: null,
          organization: null,
          id: 13,
          parameter: 13,
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
          owner: null,
          organization: null,
          id: 14,
          parameter: 14,
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
          parameter: 15,
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
          id: 10,
          owner: null,
          organization: null,
          parameter: 10,
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
          id: 11,
          owner: null,
          organization: null,
          parameter: 11,
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
          parameter: 12,
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
          owner: null,
          organization: null,
          id: 13,
          parameter: 13,
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
          owner: null,
          organization: null,
          id: 14,
          parameter: 14,
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
          parameter: 15,
        },
      ],
    };
  });

  test("plugins config form - field (no org)", async () => {
    useOrganizationStore.mockImplementation(
      jest.fn((state) => state(mockedUseOrganizationStoreNoOrg)),
    );
    const { container } = render(
      <BrowserRouter>
        <PluginConfigForm
          pluginName="AbuseIPDB"
          pluginType="analyzer"
          configType={PluginConfigTypes.USER_CONFIG}
          configs={configs.user_config}
          isUserOwnerOrAdmin={false}
          refetch={() => jest.fn()}
          toggle={() => jest.fn()}
        />
      </BrowserRouter>,
    );

    // USER CONFIG
    // int - default config
    expect(screen.getByText("int_input")).toBeInTheDocument();
    const inputValue = container.querySelector(
      "#pluginConfig_userConfig-int_input",
    );
    expect(inputValue).toBeInTheDocument();
    expect(inputValue).toHaveValue(180);
    const firstClearButton = container.querySelector(
      "#pluginConfig_userConfig-int_input-deletebtn",
    );
    expect(firstClearButton).toBeInTheDocument();
    expect(firstClearButton.className).toContain("disabled");
    // bool - user config
    expect(screen.getByText("bool_input")).toBeInTheDocument();
    const trueValue = screen.getByRole("radio", { name: "true" });
    expect(trueValue).toBeInTheDocument();
    expect(trueValue).not.toBeChecked();
    const falseValue = screen.getByRole("radio", { name: "false" });
    expect(falseValue).toBeInTheDocument();
    expect(falseValue).toBeChecked();
    const secondClearButton = container.querySelector(
      "#pluginConfig_userConfig-bool_input-deletebtn",
    );
    expect(secondClearButton).toBeInTheDocument();
    expect(secondClearButton.className).not.toContain("disabled");
    // str - secret required - no config
    const strLabel = screen.getByText("str_input");
    expect(strLabel).toBeInTheDocument();
    expect(strLabel.className).toContain("required");
    const strValue = container.querySelector(
      "#pluginConfig_userConfig-str_input",
    );
    expect(strValue).toBeInTheDocument();
    const thirdClearButton = container.querySelector(
      "#pluginConfig_userConfig-str_input-deletebtn",
    );
    expect(thirdClearButton).toBeInTheDocument();
    expect(thirdClearButton.className).toContain("disabled");
    // float - default config
    const floatValue = container.querySelector(
      "#pluginConfig_userConfig-float_input",
    );
    expect(floatValue).toBeInTheDocument();
    expect(floatValue).toHaveValue(10.5);
    const fourthClearButton = container.querySelector(
      "#pluginConfig_userConfig-float_input-deletebtn",
    );
    expect(fourthClearButton).toBeInTheDocument();
    expect(fourthClearButton.className).toContain("disabled");
    // list - default config
    const listContainer = container.querySelector(
      "#pluginConfig_userConfig-list_input",
    );
    expect(listContainer).toBeInTheDocument();
    const listValue1 = container.querySelector("#userConfig__value-0");
    expect(listValue1).toBeInTheDocument();
    expect(listValue1).toHaveValue("list value 1");
    expect(
      container.querySelector("#userConfig__value-0-deletebtn"),
    ).toBeInTheDocument();
    const listValue2 = container.querySelector("#userConfig__value-1");
    expect(listValue2).toBeInTheDocument();
    expect(listValue2).toHaveValue("list value 2");
    expect(
      container.querySelector("#userConfig__value-1-deletebtn"),
    ).toBeInTheDocument();
    const fifthClearButton = container.querySelector(
      "#pluginConfig_userConfig-list_input-deletebtn",
    );
    expect(fifthClearButton).toBeInTheDocument();
    expect(fifthClearButton.className).toContain("disabled");
    // dict - secret required - no config
    const dictInput = screen.getByText("dict_input");
    expect(dictInput).toBeInTheDocument();
    const sixthClearButton = container.querySelector(
      "#pluginConfig_userConfig-dict_input-deletebtn",
    );
    expect(sixthClearButton).toBeInTheDocument();
    expect(sixthClearButton.className).toContain("disabled");

    const saveButton = screen.getByRole("button", { name: "Save" });
    expect(saveButton).toBeInTheDocument();
  });

  test("plugins config form - field (org owner)", async () => {
    useOrganizationStore.mockImplementation(
      jest.fn((state) => state(mockedUseOrganizationStoreOwner)),
    );

    const { container } = render(
      <BrowserRouter>
        <PluginConfigForm
          pluginName="AbuseIPDB"
          pluginType="analyzer"
          configType={PluginConfigTypes.ORG_CONFIG}
          configs={configs.organization_config}
          isUserOwnerOrAdmin
          refetch={() => jest.fn()}
          toggle={() => jest.fn()}
        />
      </BrowserRouter>,
    );

    // ORG CONFIG
    // int - default config
    expect(screen.getByText("int_input")).toBeInTheDocument();
    const inputValue = container.querySelector(
      "#pluginConfig_orgConfig-int_input",
    );
    expect(inputValue).toBeInTheDocument();
    expect(inputValue).toHaveValue(180);
    const firstClearButton = container.querySelector(
      "#pluginConfig_orgConfig-int_input-deletebtn",
    );
    expect(firstClearButton).toBeInTheDocument();
    expect(firstClearButton.className).toContain("disabled");
    // bool - default config
    expect(screen.getByText("bool_input")).toBeInTheDocument();
    const trueValue = screen.getByRole("radio", { name: "true" });
    expect(trueValue).toBeInTheDocument();
    expect(trueValue).toBeChecked();
    const falseValue = screen.getByRole("radio", { name: "false" });
    expect(falseValue).toBeInTheDocument();
    expect(falseValue).not.toBeChecked();
    const secondClearButton = container.querySelector(
      "#pluginConfig_orgConfig-bool_input-deletebtn",
    );
    expect(secondClearButton).toBeInTheDocument();
    expect(secondClearButton.className).toContain("disabled");
    // str - secret required - no config
    const strLabel = screen.getByText("str_input");
    expect(strLabel).toBeInTheDocument();
    expect(strLabel.className).toContain("required");
    const strValue = container.querySelector(
      "#pluginConfig_orgConfig-str_input",
    );
    expect(strValue).toBeInTheDocument();
    const thirdClearButton = container.querySelector(
      "#pluginConfig_orgConfig-str_input-deletebtn",
    );
    expect(thirdClearButton).toBeInTheDocument();
    expect(thirdClearButton.className).toContain("disabled");
    // float - default config
    const floatValue = container.querySelector(
      "#pluginConfig_orgConfig-float_input",
    );
    expect(floatValue).toBeInTheDocument();
    expect(floatValue).toHaveValue(10.5);
    const fourthClearButton = container.querySelector(
      "#pluginConfig_orgConfig-float_input-deletebtn",
    );
    expect(fourthClearButton).toBeInTheDocument();
    expect(fourthClearButton.className).toContain("disabled");
    // list - default config
    const listContainer = container.querySelector(
      "#pluginConfig_orgConfig-list_input",
    );
    expect(listContainer).toBeInTheDocument();
    const listValue1 = container.querySelector("#orgConfig__value-0");
    expect(listValue1).toBeInTheDocument();
    expect(listValue1).toHaveValue("list value 1");
    expect(
      container.querySelector("#orgConfig__value-0-deletebtn"),
    ).toBeInTheDocument();
    const listValue2 = container.querySelector("#orgConfig__value-1");
    expect(listValue2).toBeInTheDocument();
    expect(listValue2).toHaveValue("list value 2");
    expect(
      container.querySelector("#orgConfig__value-1-deletebtn"),
    ).toBeInTheDocument();
    const fifthClearButton = container.querySelector(
      "#pluginConfig_orgConfig-list_input-deletebtn",
    );
    expect(fifthClearButton).toBeInTheDocument();
    expect(fifthClearButton.className).toContain("disabled");
    // dict - secret required - no config
    const dictInput = screen.getByText("dict_input");
    expect(dictInput).toBeInTheDocument();
    const sixthClearButton = container.querySelector(
      "#pluginConfig_orgConfig-dict_input-deletebtn",
    );
    expect(sixthClearButton).toBeInTheDocument();
    expect(sixthClearButton.className).toContain("disabled");

    const saveButtonOrg = screen.getByRole("button", { name: "Save" });
    expect(saveButtonOrg).toBeInTheDocument();
  });

  test("plugins config form - field (org user)", async () => {
    useOrganizationStore.mockImplementation(
      jest.fn((state) => state(mockedUseOrganizationStoreUser)),
    );

    const { container } = render(
      <BrowserRouter>
        <PluginConfigForm
          pluginName="AbuseIPDB"
          pluginType="analyzer"
          configType={PluginConfigTypes.ORG_CONFIG}
          configs={configs.organization_config}
          isUserOwnerOrAdmin={false}
          refetch={() => jest.fn()}
          toggle={() => jest.fn()}
        />
      </BrowserRouter>,
    );

    // ORG CONFIG
    // int - default config
    expect(screen.getByText("int_input")).toBeInTheDocument();
    const inputValue = container.querySelector(
      "#pluginConfig_orgConfig-int_input",
    );
    expect(inputValue).toBeInTheDocument();
    expect(inputValue).toHaveValue(180);
    expect(inputValue.className).toContain("disabled"); // user can't update org config
    const firstClearButton = container.querySelector(
      "#pluginConfig_orgConfig-int_input-deletebtn",
    );
    expect(firstClearButton).toBeInTheDocument();
    expect(firstClearButton.className).toContain("disabled"); // user can't delete org config
    // bool - default config
    expect(screen.getByText("bool_input")).toBeInTheDocument();
    const trueValue = screen.getByRole("radio", { name: "true" });
    expect(trueValue).toBeInTheDocument();
    expect(trueValue).toBeChecked();
    const falseValue = screen.getByRole("radio", { name: "false" });
    expect(falseValue).toBeInTheDocument();
    expect(falseValue).not.toBeChecked();
    const secondClearButton = container.querySelector(
      "#pluginConfig_orgConfig-bool_input-deletebtn",
    );
    expect(secondClearButton).toBeInTheDocument();
    expect(secondClearButton.className).toContain("disabled"); // user can't delete org config
    // str - secret required - no config
    const strLabel = screen.getByText("str_input");
    expect(strLabel).toBeInTheDocument();
    expect(strLabel.className).toContain("required");
    const strValue = container.querySelector(
      "#pluginConfig_orgConfig-str_input",
    );
    expect(strValue).toBeInTheDocument();
    expect(strValue.className).toContain("disabled"); // user can't update org config
    const thirdClearButton = container.querySelector(
      "#pluginConfig_orgConfig-str_input-deletebtn",
    );
    expect(thirdClearButton).toBeInTheDocument();
    expect(thirdClearButton.className).toContain("disabled"); // user can't delete org config
    // float - default config
    const floatValue = container.querySelector(
      "#pluginConfig_orgConfig-float_input",
    );
    expect(floatValue).toBeInTheDocument();
    expect(floatValue).toHaveValue(10.5);
    expect(floatValue.className).toContain("disabled"); // user can't update org config
    const fourthClearButton = container.querySelector(
      "#pluginConfig_orgConfig-float_input-deletebtn",
    );
    expect(fourthClearButton).toBeInTheDocument();
    expect(fourthClearButton.className).toContain("disabled"); // user can't delete org config
    // list - default config
    const listContainer = container.querySelector(
      "#pluginConfig_orgConfig-list_input",
    );
    expect(listContainer).toBeInTheDocument();
    const listValue1 = container.querySelector("#orgConfig__value-0");
    expect(listValue1).toBeInTheDocument();
    expect(listValue1).toHaveValue("list value 1");
    expect(listValue1.className).toContain("disabled"); // user can't update org config
    expect(
      container.querySelector("#orgConfig__value-0-deletebtn"),
    ).toBeInTheDocument();
    const listValue2 = container.querySelector("#orgConfig__value-1");
    expect(listValue2).toBeInTheDocument();
    expect(listValue2).toHaveValue("list value 2");
    expect(listValue2.className).toContain("disabled"); // user can't update org config
    expect(
      container.querySelector("#orgConfig__value-1-deletebtn"),
    ).toBeInTheDocument();
    const fifthClearButton = container.querySelector(
      "#pluginConfig_orgConfig-list_input-deletebtn",
    );
    expect(fifthClearButton).toBeInTheDocument();
    expect(fifthClearButton.className).toContain("disabled"); // user can't delete org config
    // dict - secret required - no config
    const dictInput = screen.getByText("dict_input");
    expect(dictInput).toBeInTheDocument();
    const sixthClearButton = container.querySelector(
      "#pluginConfig_orgConfig-dict_input-deletebtn",
    );
    expect(sixthClearButton).toBeInTheDocument();
    expect(sixthClearButton.className).toContain("disabled"); // user can't delete org config

    const saveButtonOrg = screen.getByRole("button", { name: "Save" });
    expect(saveButtonOrg).toBeInTheDocument();
  });

  test("plugins config form - create config (no org)", async () => {
    const user = userEvent.setup();
    useOrganizationStore.mockImplementation(
      jest.fn((state) => state(mockedUseOrganizationStoreNoOrg)),
    );

    // edit user_config to have only default value
    configs.user_config[1].owner = null; // bool input

    const { container } = render(
      <BrowserRouter>
        <PluginConfigForm
          pluginName="AbuseIPDB"
          pluginType="analyzer"
          configType={PluginConfigTypes.USER_CONFIG}
          configs={configs.user_config}
          isUserOwnerOrAdmin={false}
          refetch={() => jest.fn()}
          toggle={() => jest.fn()}
        />
      </BrowserRouter>,
    );

    // USER CONFIG
    // int - default config
    const intValue = container.querySelector(
      "#pluginConfig_userConfig-int_input",
    );
    expect(intValue).toBeInTheDocument();
    expect(intValue).toHaveValue(180);
    // bool - default config
    expect(screen.getByText("bool_input")).toBeInTheDocument();
    const trueValue = screen.getByRole("radio", { name: "true" });
    expect(trueValue).toBeInTheDocument();
    expect(trueValue).not.toBeChecked();
    const falseValue = screen.getByRole("radio", { name: "false" });
    expect(falseValue).toBeInTheDocument();
    expect(falseValue).toBeChecked();
    // str - secret required - no config
    const strValue = container.querySelector(
      "#pluginConfig_userConfig-str_input",
    );
    expect(strValue).toBeInTheDocument();
    // float - default config
    const floatValue = container.querySelector(
      "#pluginConfig_userConfig-float_input",
    );
    expect(floatValue).toBeInTheDocument();
    expect(floatValue).toHaveValue(10.5);
    // list - default config
    const listContainer = container.querySelector(
      "#pluginConfig_userConfig-list_input",
    );
    expect(listContainer).toBeInTheDocument();
    const listValue1 = container.querySelector("#userConfig__value-0");
    expect(listValue1).toBeInTheDocument();
    expect(listValue1).toHaveValue("list value 1");
    expect(
      container.querySelector("#userConfig__value-0-deletebtn"),
    ).toBeInTheDocument();
    const listValue2 = container.querySelector("#userConfig__value-1");
    expect(listValue2).toBeInTheDocument();
    expect(listValue2).toHaveValue("list value 2");
    expect(
      container.querySelector("#userConfig__value-1-deletebtn"),
    ).toBeInTheDocument();
    const addNewValueBtn = screen.getByRole("button", {
      name: "Add new value",
    });
    expect(addNewValueBtn).toBeInTheDocument();
    // dict - secret required - no config
    const dictInput = screen.getByText("dict_input");
    expect(dictInput).toBeInTheDocument();
    const dictInputJson = container.querySelector(
      "#jsonAceEditor__pluginConfig_userConfig-dict_input",
    );
    expect(dictInputJson).toBeInTheDocument();

    const saveButton = screen.getByRole("button", { name: "Save" });
    expect(saveButton).toBeInTheDocument();

    fireEvent.change(intValue, { target: { value: 200 } }); // int
    await user.click(trueValue); // bool
    await user.type(strValue, "myNewSecret"); // string
    fireEvent.change(floatValue, { target: { value: 12.4 } }); // float
    // list
    await user.click(addNewValueBtn);
    const listInputElement = screen.getAllByRole("textbox", {
      name: "",
    })[2];
    await user.type(listInputElement, "newListElement");

    await user.click(saveButton);

    await waitFor(() => {
      expect(axios.post).toHaveBeenCalledWith(
        `${API_BASE_URI}/analyzer/AbuseIPDB/plugin_config`,
        [
          {
            attribute: "int_input",
            value: "200",
            analyzer_config: "AbuseIPDB",
            parameter: 10,
            for_organization: false,
          },
          {
            attribute: "bool_input",
            value: "true",
            analyzer_config: "AbuseIPDB",
            parameter: 11,
            for_organization: false,
          },
          {
            attribute: "str_input",
            value: '"myNewSecret"',
            analyzer_config: "AbuseIPDB",
            parameter: 12,
            for_organization: false,
          },
          {
            attribute: "float_input",
            value: "12.4",
            analyzer_config: "AbuseIPDB",
            parameter: 13,
            for_organization: false,
          },
          {
            attribute: "list_input",
            value: '["list value 1","list value 2","newListElement"]',
            analyzer_config: "AbuseIPDB",
            parameter: 14,
            for_organization: false,
          },
        ],
      );
    });
  });

  test("plugins config form - update config (no org)", async () => {
    const user = userEvent.setup();
    useOrganizationStore.mockImplementation(
      jest.fn((state) => state(mockedUseOrganizationStoreNoOrg)),
    );

    // edit user_config to have existing and not default values
    configs.user_config[0].owner = "user"; // int input
    configs.user_config[1].owner = "user"; // bool input
    configs.user_config[2].value = "mysecret"; // str input
    configs.user_config[2].exist = true;
    configs.user_config[2].owner = "user";
    configs.user_config[2].id = 12;
    configs.user_config[3].owner = "user"; // float input
    configs.user_config[4].owner = "user"; // list input
    configs.user_config[5].value = '{"param1": "A"}'; // dict input
    configs.user_config[5].exist = true;

    const { container } = render(
      <BrowserRouter>
        <PluginConfigForm
          pluginName="AbuseIPDB"
          pluginType="analyzer"
          configType={PluginConfigTypes.USER_CONFIG}
          configs={configs.user_config}
          refetch={() => jest.fn()}
          toggle={() => jest.fn()}
        />
      </BrowserRouter>,
    );

    // USER CONFIG
    // int - default config
    const intValue = container.querySelector(
      "#pluginConfig_userConfig-int_input",
    );
    expect(intValue).toBeInTheDocument();
    expect(intValue).toHaveValue(180);
    // bool - default config
    expect(screen.getByText("bool_input")).toBeInTheDocument();
    const trueValue = screen.getByRole("radio", { name: "true" });
    expect(trueValue).toBeInTheDocument();
    expect(trueValue).not.toBeChecked();
    const falseValue = screen.getByRole("radio", { name: "false" });
    expect(falseValue).toBeInTheDocument();
    expect(falseValue).toBeChecked();
    // str - secret required - no config
    const strValue = container.querySelector(
      "#pluginConfig_userConfig-str_input",
    );
    expect(strValue).toBeInTheDocument();
    // float - default config
    const floatValue = container.querySelector(
      "#pluginConfig_userConfig-float_input",
    );
    expect(floatValue).toBeInTheDocument();
    expect(floatValue).toHaveValue(10.5);
    // list - default config
    const listContainer = container.querySelector(
      "#pluginConfig_userConfig-list_input",
    );
    expect(listContainer).toBeInTheDocument();
    const listValue1 = container.querySelector("#userConfig__value-0");
    expect(listValue1).toBeInTheDocument();
    expect(listValue1).toHaveValue("list value 1");
    expect(
      container.querySelector("#userConfig__value-0-deletebtn"),
    ).toBeInTheDocument();
    const listValue2 = container.querySelector("#userConfig__value-1");
    expect(listValue2).toBeInTheDocument();
    expect(listValue2).toHaveValue("list value 2");
    expect(
      container.querySelector("#userConfig__value-1-deletebtn"),
    ).toBeInTheDocument();
    const addNewValueBtn = screen.getByRole("button", {
      name: "Add new value",
    });
    expect(addNewValueBtn).toBeInTheDocument();
    // dict - secret required - no config
    const dictInput = screen.getByText("dict_input");
    expect(dictInput).toBeInTheDocument();
    const dictInputJson = container.querySelector(
      "#jsonAceEditor__pluginConfig_userConfig-dict_input",
    );
    expect(dictInputJson).toBeInTheDocument();

    const saveButton = screen.getByRole("button", { name: "Save" });
    expect(saveButton).toBeInTheDocument();

    fireEvent.change(intValue, { target: { value: 200 } }); // int
    await user.click(trueValue); // bool
    await user.clear(strValue); // string
    await user.type(strValue, "myNewSecret");
    fireEvent.change(floatValue, { target: { value: 12.4 } }); // float
    // list
    await user.click(addNewValueBtn);
    const listInputElement = screen.getAllByRole("textbox", {
      name: "",
    })[2];
    await user.type(listInputElement, "newListElement");

    await user.click(saveButton);

    await waitFor(() => {
      expect(axios.patch).toHaveBeenCalledWith(
        `${API_BASE_URI}/analyzer/AbuseIPDB/plugin_config`,
        [
          {
            attribute: "int_input",
            value: "200",
            id: 10,
          },
          {
            attribute: "bool_input",
            value: "true",
            id: 11,
          },
          {
            attribute: "str_input",
            value: '"myNewSecret"',
            id: 12,
          },
          {
            attribute: "float_input",
            value: "12.4",
            id: 13,
          },
          {
            attribute: "list_input",
            value: '["list value 1","list value 2","newListElement"]',
            id: 14,
          },
        ],
      );
    });
  });

  test("plugins config form - delete config (no org)", async () => {
    const user = userEvent.setup();
    useOrganizationStore.mockImplementation(
      jest.fn((state) => state(mockedUseOrganizationStoreNoOrg)),
    );

    const { container } = render(
      <BrowserRouter>
        <PluginConfigForm
          pluginName="AbuseIPDB"
          pluginType="analyzer"
          configType={PluginConfigTypes.USER_CONFIG}
          configs={configs.user_config}
          refetch={() => jest.fn()}
          toggle={() => jest.fn()}
        />
      </BrowserRouter>,
    );

    // user config
    // int - default config
    expect(screen.getByText("int_input")).toBeInTheDocument();
    const inputValue = container.querySelector(
      "#pluginConfig_userConfig-int_input",
    );
    expect(inputValue).toBeInTheDocument();
    expect(inputValue).toHaveValue(180);
    const firstClearButton = container.querySelector(
      "#pluginConfig_userConfig-int_input-deletebtn",
    );
    expect(firstClearButton).toBeInTheDocument();
    expect(firstClearButton.className).toContain("disabled");
    // bool - user config
    expect(screen.getByText("bool_input")).toBeInTheDocument();
    const trueValue = screen.getByRole("radio", { name: "true" });
    expect(trueValue).toBeInTheDocument();
    expect(trueValue).not.toBeChecked();
    const falseValue = screen.getByRole("radio", { name: "false" });
    expect(falseValue).toBeInTheDocument();
    expect(falseValue).toBeChecked();
    const secondClearButton = container.querySelector(
      "#pluginConfig_userConfig-bool_input-deletebtn",
    );
    expect(secondClearButton).toBeInTheDocument();
    expect(secondClearButton.className).not.toContain("disabled");

    const saveButton = screen.getByRole("button", { name: "Save" });
    expect(saveButton).toBeInTheDocument();

    await user.click(secondClearButton); // delete config
    await waitFor(() => {
      expect(axios.delete).toHaveBeenCalledWith(
        `${API_BASE_URI}/plugin-config/11`,
      );
    });
  });

  test("plugins config form - create config (with org)", async () => {
    const user = userEvent.setup();
    useOrganizationStore.mockImplementation(
      jest.fn((state) => state(mockedUseOrganizationStoreOwner)),
    );

    const { container } = render(
      <BrowserRouter>
        <PluginConfigForm
          pluginName="AbuseIPDB"
          pluginType="analyzer"
          configType={PluginConfigTypes.ORG_CONFIG}
          configs={configs.organization_config}
          isUserOwnerOrAdmin
          refetch={() => jest.fn()}
          toggle={() => jest.fn()}
        />
      </BrowserRouter>,
    );

    // ORG CONFIG
    // int - default config
    const intValue = container.querySelector(
      "#pluginConfig_orgConfig-int_input",
    );
    expect(intValue).toBeInTheDocument();
    expect(intValue).toHaveValue(180);
    // bool - default config
    expect(screen.getByText("bool_input")).toBeInTheDocument();
    const trueValue = screen.getByRole("radio", { name: "true" });
    expect(trueValue).toBeInTheDocument();
    expect(trueValue).toBeChecked();
    const falseValue = screen.getByRole("radio", { name: "false" });
    expect(falseValue).toBeInTheDocument();
    expect(falseValue).not.toBeChecked();
    // str - secret required - no config
    const strValue = container.querySelector(
      "#pluginConfig_orgConfig-str_input",
    );
    expect(strValue).toBeInTheDocument();
    // float - default config
    const floatValue = container.querySelector(
      "#pluginConfig_orgConfig-float_input",
    );
    expect(floatValue).toBeInTheDocument();
    expect(floatValue).toHaveValue(10.5);
    // list - default config
    const listContainer = container.querySelector(
      "#pluginConfig_orgConfig-list_input",
    );
    expect(listContainer).toBeInTheDocument();
    const listValue1 = container.querySelector("#orgConfig__value-0");
    expect(listValue1).toBeInTheDocument();
    expect(listValue1).toHaveValue("list value 1");
    expect(
      container.querySelector("#orgConfig__value-0-deletebtn"),
    ).toBeInTheDocument();
    const listValue2 = container.querySelector("#orgConfig__value-1");
    expect(listValue2).toBeInTheDocument();
    expect(listValue2).toHaveValue("list value 2");
    expect(
      container.querySelector("#orgConfig__value-1-deletebtn"),
    ).toBeInTheDocument();
    const addNewValueBtn = screen.getByRole("button", {
      name: "Add new value",
    });
    expect(addNewValueBtn).toBeInTheDocument();
    // dict - secret required - no config
    const dictInput = screen.getByText("dict_input");
    expect(dictInput).toBeInTheDocument();
    const dictInputJson = container.querySelector(
      "#jsonAceEditor__pluginConfig_orgConfig-dict_input",
    );
    expect(dictInputJson).toBeInTheDocument();

    const saveButton = screen.getByRole("button", { name: "Save" });
    expect(saveButton).toBeInTheDocument();

    fireEvent.change(intValue, { target: { value: 200 } }); // int
    await user.click(falseValue); // bool
    await user.type(strValue, "myNewSecret"); // string
    fireEvent.change(floatValue, { target: { value: 12.4 } }); // float
    // list
    await user.click(addNewValueBtn);
    const listInputElement = screen.getAllByRole("textbox", {
      name: "",
    })[2];
    await user.type(listInputElement, "newListElement");

    await user.click(saveButton);

    await waitFor(() => {
      expect(axios.post).toHaveBeenCalledWith(
        `${API_BASE_URI}/analyzer/AbuseIPDB/plugin_config`,
        [
          {
            attribute: "int_input",
            value: "200",
            organization: mockedUseOrganizationStoreOwner.organization.name,
            analyzer_config: "AbuseIPDB",
            parameter: 10,
          },
          {
            attribute: "bool_input",
            value: "false",
            organization: mockedUseOrganizationStoreOwner.organization.name,
            analyzer_config: "AbuseIPDB",
            parameter: 11,
          },
          {
            attribute: "str_input",
            value: '"myNewSecret"',
            organization: mockedUseOrganizationStoreOwner.organization.name,
            analyzer_config: "AbuseIPDB",
            parameter: 12,
          },
          {
            attribute: "float_input",
            value: "12.4",
            organization: mockedUseOrganizationStoreOwner.organization.name,
            analyzer_config: "AbuseIPDB",
            parameter: 13,
          },
          {
            attribute: "list_input",
            value: '["list value 1","list value 2","newListElement"]',
            organization: mockedUseOrganizationStoreOwner.organization.name,
            analyzer_config: "AbuseIPDB",
            parameter: 14,
          },
        ],
      );
    });
  });
});
