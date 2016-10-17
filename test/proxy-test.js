
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

describe("verify 400 and 500 errors", function() {

    it("GET resource not found", function(done) {
        supertest(proxyUrl)
            .get("/someNonexistentEndpoint")
            .expect(http_constants.response_codes.HTTP_NOT_FOUND)
            .end(function(error) {
                if (error) {
                    throw error;
                }
                // per the HTTP spec, 404 responses should contain a response body, but not required
                done();
            });
    });

    it("GET server error", function(done) {
        supertest(proxyUrl)
            .get("/server_error")
            .expect(http_constants.response_codes.HTTP_INTERNAL_SERVER_ERROR)
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

describe("verify injection is detected in request attributes", function() {

    it("safe GET with attributes", function(done) {
        supertest(proxyUrl)
            .get("/customers/7/users/129")
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

    it("basic attribute injection GET", function(done) {
        supertest(proxyUrl)
            .get("/customers/7/users/; DROP TABLES;")
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

describe("verify more complex injection detection", function() {

    it("string equality exression (= operator)", function(done) {
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

    it("string equality exression (LIKE keyword)", function(done) {
        supertest(proxyUrl)
            .get("/default?username=tom&password=jones' OR 'test' LIKE 'test'")
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

    it("sql keyword", function(done) {
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

describe("verify error-based injection is detected", function() {

    // the attacker is trying to get MS SQL server to throw a syntax error like:
    // "syntax error converting the nvarchar value 'admin_bob' to a column of data type int"
    // which would propagate up to the view in a vulnerable webapp, allowing the attacker to see the database username
    it("error message exposing database username (MS SQL)", function(done) {
        supertest(proxyUrl)
            .get("/default?username=tom' OR 1=convertint(int, USER)")
            .expect(http_constants.response_codes.HTTP_SUCCESS_OK)
            .expect(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_TEXT_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.text, ejs.render(template, {description: patterns[3].description}));
                done();
            });
    });

    // although mysql always returns something (0, true/false, NULL, etc) rather than throw an error for invalid string casting or operations (even with strict mode),
    // it's clear that the the attacker is trying to expose the username here. mysql isn't generall vulnerable to error-based injection.
    it("error message exposing database username (mysql)", function(done) {
        supertest(proxyUrl)
            .get("/default?username=tom' OR CAST(CURRENT_USER() AS SIGNED INTEGER)")
            .expect(http_constants.response_codes.HTTP_SUCCESS_OK)
            .expect(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_TEXT_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.text, ejs.render(template, {description: patterns[2].description}));
                done();
            });
    });

});

describe("verify blind injection is detected", function() {

    /* the attacker is attempting blind (trial and error) injection; they'll keep submitting requests like:
        www.mysite.com/login?username=tom'; IF(LENGTH(CURRENT_USER)=1, SLEEP(5), false)
        www.mysite.com/login?username=tom'; IF(LENGTH(CURRENT_USER)=2, SLEEP(5), false)
        www.mysite.com/login?username=tom'; IF(LENGTH(CURRENT_USER)=3, SLEEP(5), false)

       until the site takes 5 seconds to respond, then the attacker has found the length of the DB username.
    */
    it("blind detection of DB property length (mysql)", function(done) {
        supertest(proxyUrl)
            .get("/default?username=tom'; IF(LENGTH(CURRENT_USER)=1, SLEEP(5), false)")
            .expect(http_constants.response_codes.HTTP_SUCCESS_OK)
            .expect(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_TEXT_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.text, ejs.render(template, {description: patterns[2].description}));
                done();
            });
    });

    it("blind detection of DB property length (MS SQL)", function(done) {
        supertest(proxyUrl)
            .get("/default?username=tom'; IF(LEN(USER)=1) WAITFOR DELAY '00:00:05'")
            .expect(http_constants.response_codes.HTTP_SUCCESS_OK)
            .expect(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_TEXT_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.text, ejs.render(template, {description: patterns[3].description}));
                done();
            });
    });

    /* the attacker is attempting blind (trial and error) injection; they'll keep submitting requests like:
        www.mysite.com/login?username=tom'; IF(SUBSTRING(CURRENT_USER(),1,1)='a', SLEEP(5), false)
        www.mysite.com/login?username=tom'; IF(SUBSTRING(CURRENT_USER(),1,1)='b', SLEEP(5), false)
        www.mysite.com/login?username=tom'; IF(SUBSTRING(CURRENT_USER(),1,1)='c', SLEEP(5), false)

     until the site takes 5 seconds to respond, then the attacker has found the first character of the DB username, and will move onto the second.
    */
    it("blind detection of DB property value (mysql)", function(done) {
        supertest(proxyUrl)
            .get("/default?username=tom'; IF(SUBSTRING(CURRENT_USER(),1,1)='a', SLEEP(5), false)")
            .expect(http_constants.response_codes.HTTP_SUCCESS_OK)
            .expect(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_TEXT_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.text, ejs.render(template, {description: patterns[2].description}));
                done();
            });
    });

    it("blind detection of DB property value (MS SQL)", function(done) {
        supertest(proxyUrl)
            .get("/default?username=tom'; IF(SUBSTRING(USER,1,1)='a') WAITFOR DELAY '00:00:05'")
            .expect(http_constants.response_codes.HTTP_SUCCESS_OK)
            .expect(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_TEXT_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.text, ejs.render(template, {description: patterns[3].description}));
                done();
            });
    });

    // same as above, but with hex representations of characters.
    it("blind detection of DB property value (hexadecimal) (mysql)", function(done) {
        supertest(proxyUrl)
            .get("/default?username=tom'; IF(SUBSTRING(CURRENT_USER(),1,1)=X'97', SLEEP(5), false)")
            .expect(http_constants.response_codes.HTTP_SUCCESS_OK)
            .expect(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_TEXT_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.text, ejs.render(template, {description: patterns[2].description}));
                done();
            });
    });

    it("blind detection of DB property value (hexadecimal) (MS SQL)", function(done) {
        supertest(proxyUrl)
            .get("/default?username=tom'; IF(SUBSTRING(USER,1,1)=97) WAITFOR DELAY '00:00:05'")
            .expect(http_constants.response_codes.HTTP_SUCCESS_OK)
            .expect(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_TEXT_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.text, ejs.render(template, {description: patterns[3].description}));
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