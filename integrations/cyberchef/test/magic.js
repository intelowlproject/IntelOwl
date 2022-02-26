import assert from "assert";
import request from "supertest";
import app from "../app";

describe("POST /magic", function() {
    it("should error helpfully if there's no `input` property in request body", (done) => {
        request(app)
            .post("/magic")
            .send({})
            .expect(400)
            .expect("'input' property is required in request body", done);
    });

    it("should return JSON when given some input, without content-type header", (done) => {
        request(app)
            .post("/magic")
            .send({input: "WUagwsiae6mP8gNtCCLUFpCpCB26RmBDoDD8PacdAmzAzBVjkK2QstFXaKhpC6iUS7RHqXrJtFisoRSgoJ4whjm1arm864qaNq4RcfUmLHrcsAaZc5TXCYifNdgS83gDeejGX46gaiMyuBV6EskHt1scgJ88x2tNSotQDwbGY1mmCob2ARGFvCKYNqiN9ipMq1ZU1mgkdbNuGcb76aRtYWhCGUc8g93UJudhb8htsheZnwTpgqhx83SVJSZXMXUjJT2zmpC7uXWtumqokbdSi88YtkWDAc1Toouh2oH4D4ddmNKJWUDpMwmngUmK14xwmomccPQE9hM172APnSqwxdKQ172RkcAsysnmj5gGtRmVNNh2s359wr6mS2QRP"})
            .expect(200)
            .expect(response => {
                assert.ok(response);
                assert.ok(response.body);
                assert.ok(response.body.value);
                assert.ok(response.body.type);
                assert.deepEqual(response.body.type, 6); // 6 is Dish.JSON enum value
            })
            .end((err, res) => {
                if (err) {
                    return done(err);
                }
                return done();
            });
    });

    it("should apply optional arguments provided as an object", (done) => {
        request(app)
            .post("/magic")
            .send({
                input: "WUagwsiae6mP8gNtCCLUFpCpCB26RmBDoDD8PacdAmzAzBVjkK2QstFXaKhpC6iUS7RHqXrJtFisoRSgoJ4whjm1arm864qaNq4RcfUmLHrcsAaZc5TXCYifNdgS83gDeejGX46gaiMyuBV6EskHt1scgJ88x2tNSotQDwbGY1mmCob2ARGFvCKYNqiN9ipMq1ZU1mgkdbNuGcb76aRtYWhCGUc8g93UJudhb8htsheZnwTpgqhx83SVJSZXMXUjJT2zmpC7uXWtumqokbdSi88YtkWDAc1Toouh2oH4D4ddmNKJWUDpMwmngUmK14xwmomccPQE9hM172APnSqwxdKQ172RkcAsysnmj5gGtRmVNNh2s359wr6mS2QRP",
                args: {
                    depth: 1,
                },
            })
            .expect(200)
            .expect(response => {
                assert.ok(Array.isArray(response.body.value));
                assert.strictEqual(response.body.value.length, 2); // This would be longer if depth was default 3
            })
            .end((err, result) => {
                if (err) {
                    return done(err);
                }
                done();
            });
    });

    it("should apply optional arguments provided as an array", (done) => {
        request(app)
            .post("/magic")
            .send({
                input: "WUagwsiae6mP8gNtCCLUFpCpCB26RmBDoDD8PacdAmzAzBVjkK2QstFXaKhpC6iUS7RHqXrJtFisoRSgoJ4whjm1arm864qaNq4RcfUmLHrcsAaZc5TXCYifNdgS83gDeejGX46gaiMyuBV6EskHt1scgJ88x2tNSotQDwbGY1mmCob2ARGFvCKYNqiN9ipMq1ZU1mgkdbNuGcb76aRtYWhCGUc8g93UJudhb8htsheZnwTpgqhx83SVJSZXMXUjJT2zmpC7uXWtumqokbdSi88YtkWDAc1Toouh2oH4D4ddmNKJWUDpMwmngUmK14xwmomccPQE9hM172APnSqwxdKQ172RkcAsysnmj5gGtRmVNNh2s359wr6mS2QRP",
                args: [1, true, false, ""],
            })
            .expect(200)
            .expect(response => {
                assert.ok(Array.isArray(response.body.value));
                assert.strictEqual(response.body.value.length, 24); // intensive language support true => lots of suggestions
            })
            .end((err, result) => {
                if (err) {
                    return done(err);
                }
                done();
            });
    });

});
