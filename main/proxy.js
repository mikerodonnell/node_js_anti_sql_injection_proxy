
'use strict';

// Node JS imports
var http = require('http');
var querystring = require('querystring');
var url = require('url');

// local imports
var config = require('../config');
var http_constants = require('../http-constants');
var patterns = require('./patterns');

var server = http.createServer();


function handleRequest(proxiedRequest, proxiedResponse) {
	console.log("handling request");
	
	var requestBody = "";

	function handleRequestData(data) {
		requestBody += data;
	}

	function handleRequestEnd() {

		function handleResponse(rawResponse) {

			var targetResponse = "";

			rawResponse.setEncoding('utf8');

			rawResponse.on("data", function(data) {
				targetResponse += data; // for each data event, append the incoming chunked response data
			});

			rawResponse.on('end', function() {
				for(var headerKey in rawResponse.headers)
					proxiedResponse.setHeader(headerKey, rawResponse.headers[headerKey]);

				proxiedResponse.write(targetResponse);
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

		if ( scanParameters(getProxiedRequestParams(proxiedRequest, requestBody)) ) { // call getProxiedRequestParams() to get our request's params, and pass them along for scanning
			proxiedResponse.statusCode = http_constants.response_codes.HTTP_SUCCESS_OK; // 200 is default, but being explicit
			proxiedResponse.setHeader(http_constants.headers.HEADER_KEY_CONTENT, http_constants.headers.HEADER_VALUE_TEXT);
			proxiedResponse.write("request rejected, SQL injection attempt suspected");
			proxiedResponse.end(); // call proxiedResponse.end() to mark the proxiedResponse complete, sets proxiedResponse.finish to true
		} else {
			handleRawRequest();
		}
	}
	
	proxiedRequest.on('data', handleRequestData);
	
	proxiedRequest.on('end', handleRequestEnd);
}

function listeningCallback() {
	console.log("proxy started, listening on port " + config.proxy_port);
}

server.on('request', handleRequest);

server.listen(config.proxy_port, listeningCallback);


/**
 * gather all parameters from the request being proxied, both from the query string and the request body, into a single object. for example, given the query string:
 * 		?username=rmarsh&password=beer
 *
 * and the request body:
 * 		{
 * 			"username": "randy.marsh",
 * 			"firstName": "randy",
 * 			"lastName": "marsh"
 * 		}
 *
 * return:
 *  {
 *  	query.username: "rmarsh",
 *  	query.password: "beer",
 *  	body.username: "randy.marsh",
 *  	body.firstName: "randy",
 *  	body.lastName: "marsh"
 *  }
 *
 * this ensures potential collisions between query string and request body are avoided, and callers get all parameters to scan as desired. it's not this function's concern
 * that query string and request body are usually mutually exclusvie, or that request body on GET/DELETE/OPTIONS requests would likely be ignored by the server anyway;
 * just return everything.
 *
 * @param proxiedRequest
 * @param requestBody
 * @returns {{}}
 */
function getProxiedRequestParams(proxiedRequest, requestBody) {

	var requestParams = {};

	var url_parts = url.parse(proxiedRequest.url, true); // url#parse() breaks a URI string into an Object of individual parts, one of the parts being the query string
	if(url_parts.query != null) { // a query string is only expected for GET, DELETE, and HEAD, but always process it if found
		for(var key in url_parts.query) {
			requestParams["query."+key] = url_parts.query[key];
		}
	}

	if(requestBody != null) { // a request body is only expected for POST and PUT, but always process it if found
		var body = querystring.parse(requestBody);
		for(var key in body) {
			requestParams["body."+key] = body[key];
		}
	}

	return requestParams;
}


/**
 * given an incoming request being proxied, build a configuration options Object for the raw request that will be passed along to the server. for the most part this just
 * involves copying over properties from the proxied request, with substitutions for host, port, and a few headers.
 *
 * @param proxiedRequest
 * @returns {{hostname: string, port: number, method: (*|chainableBehavior.method|string|method|parserOnHeadersComplete.incoming.method|IncomingMessage.method), path: string, headers: {}}}
 */
function getRawRequestOptions(proxiedRequest) {

	var relativePath = proxiedRequest.url;
	if(proxiedRequest.url.substring(0, 1)=="/")
		relativePath = relativePath.substring(1, relativePath.length);

	// there are certain headers, namely "host", which we don't want to pass along. the rest should pass through to the destination.
	var rawRequestHeaders = {};
	if(typeof proxiedRequest.headers != 'undefined' && proxiedRequest.headers != null) { // if the proxied request has any headers ...
		rawRequestHeaders = Object.create(proxiedRequest.headers); // ... then copy all of them into our headers for our raw request ...
		delete rawRequestHeaders.host; // ... except omit the "host" header from our raw request
	}

	/* copy the request method, path+query params, and headers from the user's proxied request to our outbound request to the real destination. only the
	   hostname and port will be different. it's worth noting that for POST/PUT, the Content-Length header must match the request body. so if we were to
	   modify the request body at any point in our proxying, we'd have to update Content-Length as well.
	*/
	var requestOptions = {
		"hostname": config.target_host,
		"port": config.target_port,
		"method": proxiedRequest.method,
		"path": "/" + relativePath,
		"headers": rawRequestHeaders
	}

	return requestOptions;
}


/**
 * scan the given parameters object and return true if any parameter value contains suspicious SQL injection text. returns false or null or empty
 * parameters.
 *
 * @param parameters
 * @returns {boolean}
 */
function scanParameters(parameters) {

	if(parameters!=null) {
		for (var key in parameters) {
			for (var index = 0; index < patterns.length; index++) {
				if (patterns[index].regex.test( parameters[key] )) { // does this SQL injection regex match the value of this param?
					console.log("suspicious parameter identified: " + patterns[index].description);
					return true; // return, no need to scan rest of the parameters
				}
			}
		}
	}

	return false;
}