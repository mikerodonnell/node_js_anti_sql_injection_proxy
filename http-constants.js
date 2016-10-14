
'use strict';

var http_constants = {};

var response_codes = {};
response_codes.HTTP_SUCCESS_OK = 200;
response_codes.HTTP_NOT_FOUND = 404;
response_codes.HTTP_INTERNAL_SERVER_ERROR = 500;

var headers = {};
headers.HEADER_KEY_CONTENT = 'Content-Type';
headers.HEADER_VALUE_FORM = 'application/x-www-form-urlencoded';
headers.HEADER_VALUE_TEXT = 'text/html';
headers.HEADER_VALUE_JSON = 'application/json';
headers.HEADER_VALUE_JSON_REGEX = /application\/json/; // using regex to match "application/json" OR things like "application/json; charset=UTF-8"
headers.HEADER_VALUE_TEXT_REGEX = /text\/html/;

var error_codes = {};
error_codes.UNRESOLVED_HOST = 'ENOTFOUND';

http_constants.response_codes = response_codes;
http_constants.headers = headers;
http_constants.error_codes = error_codes;
module.exports = http_constants;