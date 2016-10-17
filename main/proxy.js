
"use strict";

// Node JS imports
var ejs = require("ejs");
var fs = require("fs");
var http = require("http");
var https = require("https");
var querystring = require("querystring");
var url = require("url");

// local imports
var config = require("../config");
var httpConstants = require("../http-constants");
var patterns = require("./patterns");


// initialize the Node server
var server = http.createServer();

// start the server, listening at localhost on the port configured in config.js
server.listen(config.proxyPort, handleListening);

// any time the "request" event is emitted by the Node server, invoke our #handleRequest method
server.on("request", handleRequest);


/** callback invoked once when the proxy server starts up */
function handleListening() {
	console.log("proxy started, listening on port " + config.proxyPort);
}


/**
 * callback invoked each time an HTTP request comes in to the proxy server
 *
 * @param proxiedRequest an instance of http.IncomingMessage. the request from the user to the proxy server (to localhost)
 * @param proxiedResponse an instance of http.ServerResponse. the response from the proxy server to the user. this will either be the response passed along from the destination website/application,
 * or, if SQL injection was detected, a response originating from the proxy saying the request was blocked.
 */
function handleRequest(proxiedRequest, proxiedResponse) {
	console.log("handling request");
	
	var requestBody = "";

	function handleRequestData(data) {
		requestBody += data;
	}

	function handleRequestEnd() {

		function handleResponse(rawResponse) {
			// first copy the headers, including the HTTP status code, from the raw response into proxied response to the end user
			proxiedResponse.writeHead(rawResponse.statusCode, rawResponse.headers);

			// now pipe the raw response body directly into the proxied response to the end user
			rawResponse.pipe(proxiedResponse);

			// all done. we don't need to watch for rawResponse's 'end' event.
		}

		function handleRawRequest() {
			var requestOptions = getRawRequestOptions(proxiedRequest);

			console.log("firing " + (requestOptions.port === 443 ? "SSL" : "non-SSL") + " request to: ");
			console.log(requestOptions);

			var request = null;
			if (requestOptions.port === 443 || config.forceSSL) // use SSL if the target (raw) port is 443, OR if the user has set the force_ssl flag
				request = https.request(requestOptions, handleResponse);
			else // default to non-SSL
				request = http.request(requestOptions, handleResponse);

			request.on("error", function(error) {
				if (httpConstants.errorCodes.UNRESOLVED_HOST === error.code) {
					// unknown host ... config.target_host in config.js is either wrong, or down
					proxiedResponse.write("Could not resolve host: " + requestOptions.hostname);
				}
				else {
					// we don't expect this to ever happen, throw generic message
					console.log(error);
					proxiedResponse.write("unknown proxy error occurred.");
				}

				proxiedResponse.end(); // close our response to our caller now, nothing left to do.
			});
			
			// copy the request body from the incoming user's request (proxied request) to our outgoing request to the real destination.
			// the request body it separate from the requestOptions (method, url, protocol, etc), which are handled by getRawRequestOptions().
			// request body is not applicable to GET requests, but doesn't hurt.
			request.write(requestBody);
			request.end();
		}

		// call getProxiedRequestParams() to get our request's params, and pass them along for scanning
		var blockedReason = scanParameters(getProxiedRequestParams(proxiedRequest, requestBody));
		
		if(blockedReason) { // scanParameters() returns a reason the request should be blocked, if any.
			proxiedResponse.statusCode = httpConstants.responseCodes.HTTP_SUCCESS_OK; // 200 is default, but being explicit

			if(proxiedRequest.method === "GET") { // respond to blocked GET requests with HTML. presumably the request is from a browser, though no way to be sure.
				proxiedResponse.setHeader(httpConstants.headers.HEADER_KEY_CONTENT, httpConstants.headers.HEADER_VALUE_TEXT);
				proxiedResponse.write(renderBlockedHTML(blockedReason)); // render our variables into the template and write the whole string as our response body
			}
			else { // respond to all other blocked requests with JSON. they're not originating from a browser.
				proxiedResponse.setHeader(httpConstants.headers.HEADER_KEY_CONTENT, httpConstants.headers.HEADER_VALUE_JSON);
				proxiedResponse.write(renderBlockedJSON(blockedReason)); // render our variables into the template and write the whole string as our response body
			}

			proxiedResponse.end(); // call proxiedResponse.end() to mark the proxiedResponse complete, sets proxiedResponse.finish to true
		} else {
			handleRawRequest();  // scanParameters() returns null for requests that have been verified benign
		}
	}
	
	proxiedRequest.on("data", handleRequestData);
	
	proxiedRequest.on("end", handleRequestEnd);
}


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
	var key = "";

	var urlParts = url.parse(proxiedRequest.url, true); // url#parse() breaks a URI string into an Object of individual parts, one of the parts being the query string
	if(urlParts.query !== null) { // a query string is only expected for GET, DELETE, and HEAD, but always process it if found
		for(key in urlParts.query) {
			if(urlParts.query.hasOwnProperty(key))
				requestParams["query."+key] = urlParts.query[key];
		}
	}

	if(requestBody !== null) { // a request body is only expected for POST and PUT, but always process it if found
		var body = querystring.parse(requestBody);
		for(key in body) {
			if(body.hasOwnProperty(key))
				requestParams["body."+key] = body[key];
		}
	}

	// get URL attributes too, like /api/users/129, or /api/customers/7/users/129
	var urlAttributes = urlParts.pathname.split("/");
	for(var index=0; index<urlAttributes.length; index++) {
		// since attributes aren't key value pairs, just values, the value of key here will be 0, 1, 2, etc. doesn't affect anything
		if(urlAttributes[index].length > 0)
			requestParams["pathname."+index] = decodeURIComponent(urlAttributes[index]); // example: pathname.1=129
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
	if(proxiedRequest.url.substring(0, 1) === "/")
		relativePath = relativePath.substring(1, relativePath.length);

	// there are certain headers, namely "host", which we don't want to pass along. the rest should pass through to the destination.
	var rawRequestHeaders = {};
	if(typeof proxiedRequest.headers !== "undefined" && proxiedRequest.headers !== null) { // if the proxied request has any headers ...
		// ... then copy all of them into our headers for our raw request. note that this only does a shallow copy.
		rawRequestHeaders = Object.assign({}, proxiedRequest.headers);
		delete rawRequestHeaders.host; // ... except omit the "host" header from our raw request
	}

	/* copy the request method, path+query params, and headers from the user's proxied request to our outbound request to the real destination. only the
	   hostname and port will be different. it's worth noting that for POST/PUT, the Content-Length header must match the request body. so if we were to
	   modify the request body at any point in our proxying, we'd have to update Content-Length as well.
	*/
	var requestOptions = {
		"hostname": config.targetHost,
		"port": config.targetPort,
		"method": proxiedRequest.method,
		"path": "/" + relativePath,
		"headers": rawRequestHeaders
	};

	return requestOptions;
}


/**
 * scan the given parameters object. if any parameter value contains suspicious SQL injection text, return a description of the suspicous parameter. returns null otherwise, including
 * null or empty parameters.
 *
 * @param parameters
 * @returns {boolean} a description of the suspicous parameter. ex.: "SQL command. (ex. DROP)"
 */
function scanParameters(parameters) {

	if(parameters !== null) {
		for(var key in parameters) {
			if (parameters.hasOwnProperty(key)) {
				for (var index = 0; index < patterns.length; index++) {
					if (patterns[index].regex.test(parameters[key])) { // does this SQL injection regex match the value of this param?
						console.log("suspicious parameter identified: " + patterns[index].description);
						return patterns[index].description; // return, no need to scan rest of the parameters
					}
				}
			}
		}
	}

	return null;
}


/**
 * Render the "request blocked" page with the given reason the request was deemed suspicous and thus blocked.
 *
 * @param description a string describing the reason the proxied request was blocked. ex.: "SQL command. (ex. DROP)"
 * @returns {String} the full HTML of the "request blocked" as a string.
 */
function renderBlockedHTML(description) {
	var template = fs.readFileSync(__dirname + "/view/index.html", "utf8");

	var renderData = {
		description: description
	};

	return ejs.render(template, renderData);
}


/**
 * generate the JSON response body to respond to non-browser requests letting them know their request has been blocked. this returns the raw string containing
 * JSON markup and is intended to be used with the "Content-Type: application/json" response header.
 *
 * @param description
 * @returns {String} JSON string, ex.: '{"success":false,"message":"SQL command. (ex. DROP)"}'
 */
function renderBlockedJSON(description) {
	var responseBody = {
		success: false,
		message: description
	};

	return JSON.stringify(responseBody);
}
