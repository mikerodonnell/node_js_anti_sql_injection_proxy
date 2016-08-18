
'use strict';

var http_constants = {};

var response_codes = {};
response_codes.HTTP_SUCCESS_OK = 200;

var headers = {};
headers.HEADER_KEY_CONTENT = 'Content-Type';
headers.HEADER_VALUE_TEXT = 'text/html';
headers.HEADER_VALUE_JSON_REGEX = /application\/json/; // using regex to match "application/json" OR things like "application/json; charset=UTF-8"
headers.HEADER_VALUE_TEXT_REGEX = /text\/html/;

http_constants.response_codes = response_codes;
http_constants.headers = headers;
module.exports = http_constants;