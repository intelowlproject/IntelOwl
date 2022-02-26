# Contributing

Thank you for contributing to CyberChef-server! :metal:

Please note that this repository only contains the code for the HTTP server for CyberChef. To make changes to the CyberChef tool, please go to the [CyberChef repository](https://github.com/gchq/CyberChef)

Before your contributions can be accepted, you must:

 - Sign the [GCHQ Contributor Licence Agreement](https://cla-assistant.io/gchq/CyberChef)
 - Push your changes to your fork.
 - Submit a pull request.


## Coding conventions

* Indentation: Each block should consist of 4 spaces
* Object/namespace identifiers: CamelCase
* Function/variable names: camelCase
* Constants: UNDERSCORE_UPPER_CASE
* Source code encoding: UTF-8 (without BOM)
* All source files must end with a newline
* Line endings: UNIX style (\n)

We also use [eslint](https://eslint.org/) to maintain a consistent code style. You can run `npm run lint` to run eslint - it will automatically fix any errors, if it can.