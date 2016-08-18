
'use strict';

var assert = require('assert');
var supertest = require('supertest');

var config = require('../config');
var http_constants = require('../http-constants');

var url = "http://localhost:" + config.proxy_port;

// TODO: stub out a REST service here, verify that params passed to proxy actually get to final destination

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

    it("unsafe get request test", function(done) {
        supertest(url)
            .get("/default?username=tom&password=jonesbad")
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