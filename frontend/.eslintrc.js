module.exports = {
  env: {
    browser: true,
    es2021: true,
  },
  extends: [
    "plugin:react/recommended",
    "plugin:react-hooks/recommended",
    "airbnb",
    "prettier",
  ],
  parserOptions: {
    ecmaFeatures: {
      jsx: true,
    },
    ecmaVersion: 12,
    sourceType: "module",
  },
  rules: {
    "no-console": "off",
    "react/no-unescaped-entities": "off",
    quotes: ["error", "double"],
    "comma-dangle": [
      "error",
      {
        objects: "always",
        arrays: "only-multiline",
        imports: "never",
        exports: "never",
        functions: "never",
      },
    ],
    "no-use-before-define": "off",
    "import/prefer-default-export": "off",
    "react/jsx-props-no-spreading": "off",
    "react/destructuring-assignment": "off",
    "react/prop-types": ["warn"],
    "react/function-component-definition": [
      "error",
      {
        namedComponents: "function-declaration",
        unnamedComponents: "arrow-function",
      },
    ],
    "react/no-unstable-nested-components": ["error", { allowAsProps: true, }],
    // temp
    "no-unused-vars": "off",
    "react/forbid-prop-types": "off",
  },
};
