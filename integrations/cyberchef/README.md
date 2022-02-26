# CyberChef server

[![](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/gchq/CyberChef-server/blob/master/LICENSE)
[![Gitter](https://badges.gitter.im/gchq/CyberChef.svg)](https://gitter.im/gchq/CyberChef?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)


Run CyberChef in a server and provide an API for clients to send [Cyberchef](https://gchq.github.io/CyberChef/) recipes to bake.

## Motivation

CyberChef has a useful Node.js API, but sometimes we want to be able to programmatically run CyberChef recipes in languages other than JavaScript. By running this server, you can use CyberChef operations in any language, as long as you can communicate via HTTP.

## Example use
Assuming you've downloaded the repository and are running it locally:
```bash
curl -X POST -H "Content-Type:application/json" -d '{"input":"... ---:.-.. --- -. --. --..--:.- -. -..:- .... .- -. -.- ...:..-. --- .-.:.- .-.. .-..:- .... .:..-. .. ... ....", "recipe":{"op":"from morse code", "args": {"wordDelimiter": "Colon"}}}' localhost:3000/bake
```
response:
```
{
    value: "SO LONG, AND THANKS FOR ALL THE FISH",
    type: "string"
}
```


## Features
- **Compatible with recipes saved from CyberChef**.
After using [CyberChef](https://gchq.github.io/CyberChef/) to experiment and find a suitable recipe, the exported recipe JSON can be used to post to the `/bake` endpoint. Just copy/paste it in as your `recipe` property as part of the POST body.


## Installing
- Clone the repository
- `cd` into the project and run `npm install`
- Run `npm run`
- In a browser, navigate to `localhost:3000` to see usage documentation.


### Docker
A Docker image can be built, then run by doing the following:

- `git clone https://github.com/gchq/CyberChef-server`
- `cd CyberChef-server`
- `docker build -t cyberchef-server .`
- `docker run -it --rm --name=cyberchef-server -p 3000:3000 cyberchef-server`


## API overview
> For full documentation of the API, you can find the swagger page hosted at the root url. See [Installing](#Installing) to run the application and browse the docs.

The server has two endpoints: `/bake` and `/magic`.

### `/bake`

`/bake` allows a user to POST some input and configuration for a CyberChef Recipe. The application will run the input through the recipe and return the baked operation.

This endpoint accepts a POST request with the following body:

|Parameter|Type|Description|
|---|---|---|
input|String|The input data for the recipe. Currently accepts strings.
recipe|String or Object or Array|One or more operations, with optional arguments. Uses default arguments if they're not defined here.
outputType (optional)|String|The [Data Type](https://github.com/gchq/CyberChef/wiki/Adding-a-new-operation#data-types) that you would like the result of the bake to be returned as. This will not work with `File` or `List<File>` at the moment.

#### Example: one operation, default arguments
```javascript
{
    "input": "One, two, three, four.",
    "recipe": "to decimal"
}
```

Response:
```javascript
{
    value: "79 110 101 44 32 116 119 111 44 32 116 104 114 101 101 44 32 102 111 117 114 46",
    type: "string"
}

```
> For more information on how operation names are handled, see the [Node API docs](https://github.com/gchq/CyberChef/wiki/Node-API#operation-names)


#### Example: one operation, non-default arguments by name
```javascript
{
    "input": "One, two, three, four.",
    "recipe": {
        "op": "to decimal",
        "args": {
            "delimiter": "Colon"
        }
    }
}
```
Response:
```javascript
{
    value: "79:110:101:44:32:116:119:111:44:32:116:104:114:101:101:44:32:102:111:117:114:46",
    type: "string"
}
```

#### Example: one operation, non-default arguments by position
```javascript
{
    "input": "One, two, three, four.",
    "recipe": {
        "op": "to decimal",
        "args": ["Colon"]
    }
}
```
Response:
```javascript
{
    value: "79:110:101:44:32:116:119:111:44:32:116:104:114:101:101:44:32:102:111:117:114:46",
    type: "string"
}
```

#### Example: all together
```javascript
{
    "input": "One, two, three, four.",
    "recipe": [
        {
            "op":"to decimal",
            "args": {
                "delimiter": "CRLF"
            }
        },
        {
            "op": "swap endianness",
            "args": ["Raw"]
        },
        "MD4"
    ]
}

```
Response:
```javascript
{
    value: "31d6cfe0d16ae931b73c59d7e0c089c0",
    type: "string"
}
```


#### Example: Define outputType
`toDecimal` has an outputType of `string`. Here we are asking to translate the output to a number before returning.
```javascript
{
    "input": "One, two, three, four.",
    "recipe": "to decimal",
    "outputType": "number"
}
```
Response:
```javascript
{
    // Be wary, type conversions do not always behave as expected.
    "value": 79,
    "type": "number"
}
```

### `/magic`

[Find more information about what the Magic operation does here](https://github.com/gchq/CyberChef/wiki/Automatic-detection-of-encoded-data-using-CyberChef-Magic)

The Magic operation cannot be used in conjunction with other applications in the `/bake` endpoint.


|Parameter|Type|Description|
|---|---|---|
input|String|The input data for the recipe. Currently accepts strings.
args|Object or Array|Arguments for the magic operation

#### Example: detecting hex
```javascript
{
    "input": "4f 6e 65 2c 20 74 77 6f 2c 20 74 68 72 65 65 2c 20 66 6f 75 72 2e"
}
```
Response:
```javascript
{
    "value": [
        {
            "recipe": [
                { "op": "From Hex", "args": [ "Space" ] }
            ],
            "data": "One, two, three, four.",
            "languageScores": [
                { "lang": "en", "score": 442.77940826119266, "probability": 2.8158586573567845e-12 },
                { "lang": "de", "score": 555.3142876037181, "probability": 0 },
                { "lang": "pl", "score": 560.9378201619123, "probability": 0 },
                ...
            ],
            "fileType": null,
            "isUTF8": true,
            "entropy": 3.5383105956150076,
            "matchingOps": [],
            "useful": false,
            "matchesCrib": null
        },
        ...
    ],
    "type":6
}
```


## Licencing

CyberChef-server is released under the [Apache 2.0 Licence](https://www.apache.org/licenses/LICENSE-2.0) and is covered by [Crown Copyright](https://www.nationalarchives.gov.uk/information-management/re-using-public-sector-information/copyright-and-re-use/crown-copyright/).
