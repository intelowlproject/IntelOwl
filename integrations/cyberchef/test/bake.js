import request from "supertest";
import app from "../app";


describe("GET /bake", function() {
    it("doesnt exist", function(done) {
        request(app)
            .get("/bake")
            .set("Accept", "application/json")
            .expect(404, done);
    });
});

describe("POST /bake", function() {
    it("should error helpfully if there's no `input` property in request body", (done) => {
        request(app)
            .post("/bake")
            .send({})
            .expect(400)
            .expect("'input' property is required in request body", done);
    });

    it("should error helpfully if there's no `recipe` property in request body", (done) => {
        request(app)
            .post("/bake")
            .send({input: "hello"})
            .expect(400)
            .expect("'recipe' property is required in request body", done);
    });

    it("should respond with the input if the recipe is empty", (done) => {
        request(app)
            .post("/bake")
            .send({input: "testing, one two three", recipe: []})
            .expect(200)
            .expect({
                value: "testing, one two three",
                type: "string",
            }, done);
    });

    it("should parse the recipe if it is a valid operation name", (done) => {
        request(app)
            .post("/bake")
            .set("Content-Type", "application/json")
            .send({input: "hello", recipe: "To Hexdump"})
            .expect(200)
            .expect({
                value: "00000000  68 65 6c 6c 6f                                   |hello|",
                type: "string",
            }, done);
    });

    it("should parse the recipe if it is a valid operation name string", (done) => {
        request(app)
            .post("/bake")
            .set("Content-Type", "application/json")
            .send({input: "hello", recipe: "toHexdump"})
            .expect(200)
            .expect({
                value: "00000000  68 65 6c 6c 6f                                   |hello|",
                type: "string",
            }, done);
    });

    it("should parse the recipe if it is an array of operation names", (done) => {
        request(app)
            .post("/bake")
            .set("Content-Type", "application/json")
            .send({input: "Testing, 1 2 3", recipe: ["to decimal", "MD5", "to braille"]})
            .expect(200)
            .expect({
                value: "⠲⠆⠙⠋⠲⠆⠶⠶⠖⠶⠖⠙⠋⠶⠉⠆⠃⠲⠂⠑⠲⠢⠲⠆⠲⠒⠑⠶⠲⠢⠋⠃",
                type: "string",
            }, done);
    });

    it("should parse the recipe if it is an operation with some custom arguments", (done) => {
        request(app)
            .post("/bake")
            .set("Content-Type", "application/json")
            .send({input: "Testing, 1 2 3", recipe: { op: "to hex", args: { delimiter: "Colon" }}})
            .expect(200)
            .expect({
                value: "54:65:73:74:69:6e:67:2c:20:31:20:32:20:33",
                type: "string",
            }, done);
    });

    it("should parse the recipe if it is an operation with no custom arguments", (done) => {
        request(app)
            .post("/bake")
            .set("Content-Type", "application/json")
            .send({input: "Testing, 1 2 3", recipe: {op: "to hex" }})
            .expect(200)
            .expect({
                value: "54 65 73 74 69 6e 67 2c 20 31 20 32 20 33",
                type: "string",
            }, done);
    });

    it("should parse a recipe in the compact JSON format taken from the CyberChef website", (done) => {
        request(app)
            .post("/bake")
            .set("Content-Type", "application/json")
            .send({input: "some input", recipe: [{"op": "To Morse Code", "args": ["Dash/Dot", "Backslash", "Comma"]}, {"op": "Hex to PEM", "args": ["SOMETHING"]}, {"op": "To Snake case", "args": [false]}]})
            .expect(200)
            .expect({
                value: "begin_something_anananaaaaak_da_aaak_da_aaaaananaaaaaaan_da_aaaaaaanan_da_aaak_end_something",
                type: "string",
            }, done);
    });

    it("should parse a recipe ib the clean JSON format taken from the CyberChef website", (done) => {
        request(app)
            .post("/bake")
            .set("Content-Type", "application/json")
            .send({input: "some input", recipe: [
                { "op": "To Morse Code",
                    "args": ["Dash/Dot", "Backslash", "Comma"] },
                { "op": "Hex to PEM",
                    "args": ["SOMETHING"] },
                { "op": "To Snake case",
                    "args": [false] }
            ]})
            .expect(200)
            .expect({
                value: "begin_something_anananaaaaak_da_aaak_da_aaaaananaaaaaaan_da_aaaaaaanan_da_aaak_end_something",
                type: "string",
            }, done);
    });

    it("should return a useful error if we give an input/recipe combination that results in an OperationError", (done) => {
        request(app)
            .post("/bake")
            .set("Content-Type", "application/json")
            .send({
                input: "irrelevant",
                recipe: {
                    op: "AES Encrypt",
                    args: {
                        key: "notsixteencharslong"
                    }
                }
            })
            .expect(400)
            .expect("Invalid key length: 2 bytes\n\nThe following algorithms will be used based on the size of the key:\n  16 bytes = AES-128\n  24 bytes = AES-192\n  32 bytes = AES-256", done);
    });

    it("should return a string output as a byte array, if outputType is defined", (done) => {
        request(app)
            .post("/bake")
            .set("Content-Type", "application/json")
            .send({
                input: "irregular alcove",
                recipe: "to hex",
                outputType: "byte array",
            })
            .expect(200)
            .expect({
                value: [54, 57, 32, 55, 50, 32, 55, 50, 32, 54, 53, 32, 54, 55, 32, 55, 53, 32, 54, 99, 32, 54, 49, 32, 55, 50, 32, 50, 48, 32, 54, 49, 32, 54, 99, 32, 54, 51, 32, 54, 102, 32, 55, 54, 32, 54, 53],
                type: "byteArray",
            }, done);
    });

    it("should return a json output as a number, if outputType is defined", (done) => {
        request(app)
            .post("/bake")
            .set("Content-Type", "application/json")
            .send({
                input: "something oddly colourful",
                recipe: "entropy",
                outputType: "number",
            })
            .expect(200)
            .expect({
                value: 3.893660689688185,
                type: "number",
            }, done);
    });

    it("should return a useful error if returnType is given but has an invalid value", (done) => {
        request(app)
            .post("/bake")
            .set("Content-Type", "application/json")
            .send({
                input: "irregular alcove",
                recipe: "to hex",
                outputType: "some invalid type",
            })
            .expect(400)
            .expect("Invalid data type string. No matching enum.", done);
    });

    it("should not perform MAGIC via /bake", (done) => {
        request(app)
            .post("/bake")
            .set("Content-Type", "application/json")
            .send({
                input: "You're a wizard, Harry.",
                recipe: [
                    "To Hex",
                    "Magic"
                ]
            })
            .expect(400)
            .expect("flowControl operations like Magic are not currently allowed in recipes for chef.bake in the Node API", done);
    });

});
