
'use strict';

var assert = require('assert');
var supertest = require('supertest');

var config = require('../config');
var http_constants = require('../http-constants');

var url = "http://localhost:" + config.proxy_port;


describe("sql injection test cases", function() {

    it("safe get request test", function(done) {
        supertest(url)
            .get("/default?username=tom&password=jones")
            .expect(http_constants.response_codes.HTTP_SUCCESS_OK)
            .expect(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_JSON_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                console.log(response.body);
                assert.notEqual(response.body, "");
                done();
            });
    });

    it("numeric equality expression", function(done) {
        supertest(url)
            .get("/default?username=tom&password=jones' OR 1=1")
            .expect(http_constants.response_codes.HTTP_SUCCESS_OK)
            .expect(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_TEXT_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.text, "request rejected, SQL injection attempt suspected");
                done();
            });
    });

    it("string equality exression", function(done) {
        supertest(url)
            .get("/default?username=tom&password=jones' OR 'test'='test'")
            .expect(http_constants.response_codes.HTTP_SUCCESS_OK)
            .expect(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_TEXT_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.text, "request rejected, SQL injection attempt suspected");
                done();
            });
    });

    it("sql command", function(done) {
        supertest(url)
            .get("/default?username=tom&password=jones' DROP TABLES;")
            .expect(http_constants.response_codes.HTTP_SUCCESS_OK)
            .expect(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_TEXT_REGEX)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.text, "request rejected, SQL injection attempt suspected");
                done();
            });
    });

});