
'use strict';

var httpConstants = {};

var responseCodes = {};
responseCodes.HTTP_SUCCESS_OK = 200;
responseCodes.HTTP_NOT_FOUND = 404;
responseCodes.HTTP_INTERNAL_SERVER_ERROR = 500;

var headers = {};
headers.HEADER_KEY_CONTENT = 'Content-Type';
headers.HEADER_VALUE_FORM = 'application/x-www-form-urlencoded';
headers.HEADER_VALUE_TEXT = 'text/html';
headers.HEADER_VALUE_JSON = 'application/json';
headers.HEADER_VALUE_JSON_REGEX = /application\/json/; // using regex to match "application/json" OR things like "application/json; charset=UTF-8"
headers.HEADER_VALUE_TEXT_REGEX = /text\/html/;

var errorCodes = {};
errorCodes.UNRESOLVED_HOST = 'ENOTFOUND';

httpConstants.responseCodes = responseCodes;
httpConstants.headers = headers;
httpConstants.errorCodes = errorCodes;
module.exports = httpConstants;