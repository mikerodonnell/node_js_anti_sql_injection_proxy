
var assert = require('assert');
var supertest = require('supertest');

var url = "http://localhost:8080";

var HTTP_SUCCESS_OK = 200;
var HEADER_KEY_CONTENT = 'Content-Type';
var HEADER_VALUE_JSON = /application\/json/; // using regex to match "application/json" OR things like "application/json; charset=UTF-8"
var HEADER_VALUE_TEXT = /text\/html/;

// TODO: stub out a REST service here, verify that params passed to proxy actually get to final destination

describe("sql injection test cases", function() {

    it("safe get request test", function(done) {
        supertest(url)
            .get("/default?username=tom&password=jones")
            .expect(HTTP_SUCCESS_OK)
            .expect(HEADER_KEY_CONTENT, HEADER_VALUE_JSON)
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
            .expect(HTTP_SUCCESS_OK)
            .expect(HEADER_KEY_CONTENT, HEADER_VALUE_TEXT)
            .end(function(error, response) {
                if (error) {
                    throw error;
                }
                assert.equal(response.text, "request rejected, SQL injection attempt suspected");
                done();
            });
    });

});