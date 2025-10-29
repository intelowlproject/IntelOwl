import { defineConfig } from "eslint/config";
import { fixupConfigRules } from "@eslint/compat";
import globals from "globals";
import path from "node:path";
import { fileURLToPath } from "node:url";
import js from "@eslint/js";
import { FlatCompat } from "@eslint/eslintrc";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const compat = new FlatCompat({
    baseDirectory: __dirname,
    recommendedConfig: js.configs.recommended,
    allConfig: js.configs.all
});

export default defineConfig([{
    extends: fixupConfigRules(compat.extends(
        "plugin:react/recommended",
        "plugin:react-hooks/recommended",
        "plugin:import/recommended",
        "plugin:jsx-a11y/recommended",
        "prettier",
    )),

    languageOptions: {
        globals: {
            ...globals.jest,
            ...globals.browser,
            ...globals.node,
        },

        ecmaVersion: 2021,
        sourceType: "commonjs",

        parserOptions: {
            sourceType: "module",
            ecmaFeatures: {
                legacyDecorators: true,
                jsx: true,
            },
        },
    },

    settings: {
        react: {
            version: "detect",
        },
    },

    rules: {
        "react/prop-types": ["warn"],
        "react/forbid-prop-types": "off",
        "react/jsx-props-no-spreading": "off",
        "react/jsx-fragments": ["off"],
        "no-undef": "error",
        "no-use-before-define": "off",
        "import/no-unresolved": "off",

        "id-length": ["error", {
            min: 3,
            exceptions: ["_", "id", "pk", "ip", "IP"],
        }],

        "no-warning-comments": "error",

        "no-console": ["error", {
            allow: ["debug", "error"],
        }],

        "no-unused-vars": ["error", {
            varsIgnorePattern: "^_",
            argsIgnorePattern: "^_",
            args: "after-used",
        }],

        "import/prefer-default-export": "off",
    },
}]);