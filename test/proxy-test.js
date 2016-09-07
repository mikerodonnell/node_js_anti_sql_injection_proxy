
'use strict';

var assert = require('assert');
var ejs = require("ejs");
var fs = require("fs");
var supertest = require('supertest');

var config = require('../config');
var http_constants = require('../http-constants');
var patterns = require('../main/patterns');


// basic test case data
var SAFE_QUERY_STRING = "?username=tom&password=jones";
var SAFE_BODY = {
    username: "tom",
    password: "jones"
};
var MALICIOUS_BODY = {
    username: "tom",
    password: "jones' OR 5=5"
};

var proxyUrl = "http://localhost:" + config.proxy_port;

// HTML template for response when a GET request is blocked
var template = fs.readFileSync(__dirname + "/../main/view/index.html", "utf8");


describe("verify pass-thru of safe requests", function() {

    it("safe GET no params", function(done) {
        supertest(proxyUrl)
            .get("/default")
            .expect(http_constants.response_codes.HTTP_SUCCESS_OK)
            .expect(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_JSON_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.notEqual(response.body, "");
                done();
            });
    });

    it("safe GET with params", function(done) {
        supertest(proxyUrl)
            .get("/default" + SAFE_QUERY_STRING)
            .expect(http_constants.response_codes.HTTP_SUCCESS_OK)
            .expect(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_JSON_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.notEqual(response.body, "");
                done();
            });
    });

    it("safe DELETE with params", function(done) {
        supertest(proxyUrl)
            .delete("/default" + SAFE_QUERY_STRING)
            .expect(http_constants.response_codes.HTTP_SUCCESS_OK)
            .expect(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_JSON_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.notEqual(response.body, "");
                done();
            });
    });

    it("safe POST no body", function(done) {
        supertest(proxyUrl)
            .post("/default")
            .expect(http_constants.response_codes.HTTP_SUCCESS_OK)
            .expect(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_JSON_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.notEqual(response.body, "");
                done();
            });
    });

    it("safe POST with body", function(done) {
        supertest(proxyUrl)
            .post("/default")
            .send(SAFE_BODY)
            .expect(http_constants.response_codes.HTTP_SUCCESS_OK)
            .expect(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_JSON_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.notEqual(response.body, "");
                done();
            });
    });

    it("safe PUT", function(done) {
        supertest(proxyUrl)
            .put("/default")
            .send(SAFE_BODY)
            .expect(http_constants.response_codes.HTTP_SUCCESS_OK)
            .expect(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_JSON_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.notEqual(response.body, "");
                done();
            });
    });

});

describe("verify basic injection is detected for all methods", function() {

    it("basic injection GET", function(done) {
        supertest(proxyUrl)
            .get("/default?username=tom&password=jones' OR 1=1")
            .expect(http_constants.response_codes.HTTP_SUCCESS_OK)
            .expect(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_TEXT_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.text, ejs.render(template, {description: patterns[0].description}));
                done();
            });
    });

    it("basic injection POST", function(done) {
        supertest(proxyUrl)
            .post("/default")
            .set(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_FORM)
            .send(MALICIOUS_BODY)
            .expect(http_constants.response_codes.HTTP_SUCCESS_OK)
            .expect(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_JSON_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.body.message, patterns[0].description);
                done();
            });
    });

    it("basic injection PUT", function(done) {
        supertest(proxyUrl)
            .put("/default")
            .set(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_FORM)
            .send(MALICIOUS_BODY)
            .expect(http_constants.response_codes.HTTP_SUCCESS_OK)
            .expect(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_JSON_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.body.message, patterns[0].description);
                done();
            });
    });

    it("basic injection DELETE", function(done) {
        supertest(proxyUrl)
            .delete("/default?username=tom&password=jones' OR 1=1")
            .expect(http_constants.response_codes.HTTP_SUCCESS_OK)
            .expect(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_JSON_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.body.message, patterns[0].description);
                done();
            });
    });
});

describe("verify more complex injection detection", function() {
    it("string equality exression", function(done) {
        supertest(proxyUrl)
            .get("/default?username=tom&password=jones' OR 'test'='test'")
            .expect(http_constants.response_codes.HTTP_SUCCESS_OK)
            .expect(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_TEXT_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.text, ejs.render(template, {description: patterns[0].description}));
                done();
            });
    });

    it("sql command", function(done) {
        supertest(proxyUrl)
            .get("/default?username=tom&password=jones' DROP TABLES;")
            .expect(http_constants.response_codes.HTTP_SUCCESS_OK)
            .expect(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_TEXT_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.text, ejs.render(template, {description: patterns[1].description}));
                done();
            });
    });

});

// verify that both the query string and the request body are scanned if present -- a safe query string should not "protect" a malicious body, and vice versa
describe("verify hybrid data reqests", function() {

    it("hybrid POST malicious query string", function(done) {
        supertest(proxyUrl)
            .post("/default?username=tom&password=jones DROP")
            .set(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_FORM)
            .send(SAFE_BODY)
            .expect(http_constants.response_codes.HTTP_SUCCESS_OK)
            .expect(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_JSON_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.body.message, patterns[1].description);
                done();
            });
    });

    it("hybrid POST malicious body", function(done) {
        supertest(proxyUrl)
            .post("/default" + SAFE_QUERY_STRING)
            .set(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_FORM)
            .send(MALICIOUS_BODY)
            .expect(http_constants.response_codes.HTTP_SUCCESS_OK)
            .expect(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_JSON_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.body.message, patterns[0].description);
                done();
            });
    });

});