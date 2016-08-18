
'use strict';

var RAW_PATH = "/";

var http = require('http');
var querystring = require('querystring');
var url = require('url');

var config = require('../config');
var http_constants = require('../http-constants');

var server = http.createServer();

var badStuff = "bad";

// TODO: maintain same protocol (http https)
// TODO: handle errors for unreachable host
// TODO: handle errors for reachable host that doesnt respond to the method or relative path

function handleRequest(proxiedRequest, proxiedResponse) {
	console.log("handling request");
	
	var requestBody = "";

	function handleRequestData(data) {
		requestBody += data;
	}

	function handleRequestEnd() {

		var badStuffFound = false;
		var realResponse = "initial real proxiedResponse";

		function handleResponse(rawResponse) {

			rawResponse.setEncoding('utf8');

			rawResponse.on("data", function(data) {
				realResponse = data; // TODO: test with big response that'll chunk data over several chunks. use += here?
			});

			rawResponse.on('end', function() {
				for(var headerKey in rawResponse.headers)
					proxiedResponse.setHeader(headerKey, rawResponse.headers[headerKey]);

				proxiedResponse.write(realResponse);
				proxiedResponse.end(); // call proxiedResponse.end() to mark the proxiedResponse complete, sets proxiedResponse.finish to true
			});
		}
		function handleRawRequest() {
			var requestOptions = getRawRequestOptions(proxiedRequest);

			console.log('firing request to: ');
			console.log(requestOptions);

			var request = http.request(requestOptions, handleResponse);

			// copy the request body from the incoming user's request (proxied request) to our outgoing request to the real destination.
			// the request body it separate from the requestOptions (method, url, protocol, etc), which are handled by getRawRequestOptions().
			// request body is not applicable to GET requests, but doesn't hurt.
			request.write(requestBody);
			request.end();
		}

		var requestParams = getProxiedRequestParams(proxiedRequest, requestBody);
		
		for(var key in requestParams) {
			var value = requestParams[key];
			console.log("KVP: " + key + ", " + value);
			if(value.indexOf(badStuff) > 0) {
				console.log("found bad stuff in: " + value);
				badStuffFound = true;
			}
		}

		if (badStuffFound) {
			console.log("bad stuff found!!");
			proxiedResponse.statusCode = http_constants.response_codes.HTTP_SUCCESS_OK; // 200 is default, but being explicit
			proxiedResponse.setHeader(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_TEXT);
			proxiedResponse.write("request rejected, SQL injection attempt suspected");
			proxiedResponse.end(); // call proxiedResponse.end() to mark the proxiedResponse complete, sets proxiedResponse.finish to true
		} else {
			console.log("no bad stuff found, proceeding with raw request");
			handleRawRequest();
		}
	}
	
	proxiedRequest.on('data', handleRequestData);
	
	proxiedRequest.on('end', handleRequestEnd);
}

function listeningCallback() {
	console.log("listening on port " + config.proxy_port);
}

server.on('request', handleRequest);

server.listen(config.proxy_port, listeningCallback);


function getProxiedRequestParams(proxiedRequest, requestBody) {
	var requestMethod = proxiedRequest.method;

	var requestParams = null;

	if(requestMethod === 'GET') {
		var url_parts = url.parse(proxiedRequest.url, true);
		requestParams = url_parts.query;
	}
	else if(requestMethod === 'POST') {
		requestParams = querystring.parse(requestBody);
	}
	else {
		// TODO: other HTTP methods, and proper error handling
		console.log("ERROR: unsupported HTTP method: " + requestMethod);
	}

	return requestParams;
}


function getRawRequestOptions(proxiedRequest) {

	//console.log("~~~~~~~~ proxiedRequest:")
	//console.log(proxiedRequest);

	var relativePath = proxiedRequest.url;
	if(proxiedRequest.url.substring(0, 1)=="/")
		relativePath = relativePath.substring(1, relativePath.length);

	// there are certain headers, namely "host", which we don't want to pass along as-is. the rest should pass through to the destination.
	var passThruHeaders = {};
	if(typeof proxiedRequest.headers != 'undefined' && proxiedRequest.headers != null) {
		for(var headerName in proxiedRequest.headers) {
			if(headerName != "host")
				passThruHeaders.headerName = proxiedRequest.headers[headerName];
		}
	}

	/* copy the request method, path+query params, and headers from the user's proxied request to our outbound request to the real destination. only the
	   hostname and port will be different. it's worth noting that for POST/PUT, the Content-Length header must match the request body. so if we were to
	   modify the request body at any point in our proxying, we'd have to update Content-Length as well.
	*/
	var requestOptions = {
		"hostname": config.target_host,
		"port": config.target_port,
		"method": proxiedRequest.method,
		"path": RAW_PATH + relativePath,
		"headers": passThruHeaders
	}

	return requestOptions;
}