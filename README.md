##About
A simple proxy that scans for SQL injection attacks and blocks suspicious requests. Have a vulnerable legacy application without resources or source to update it? Insert this proxy between your web server and your application.

##Usage
1. _prerequisites: [Node JS](https://nodejs.org) installed and on the system path_
1. clone the repository: `git clone git@github.com:mikerodonnell/node_js_anti_sql_injection_proxy.git`
<br>
2. edit config.js with your application base url, or any non-SSL website just to test. example: `config.target_host="http://www.xkcd.com"`
<br>
3. from within the `node_js_anti_sql_injection_proxy/` directory: `node main/proxy.js`
<br>
4. still within `node_js_anti_sql_injection_proxy/`, run unit tests: `npm test`
<br>
5. verify benign requests work through the proxy (default port is 8080): `http://localhost:8080`
<br>
<img src="example/passthru.png" width="600" height="150" />
<br>
6. verify suspicious requests are blocked: `http://localhost:8080?name=Robert') DROP TABLE students`
<br>
<img src="example/blocked.png" width="600" height="150" />

##Tools used
* [mocha](https://mochajs.org/) _unit testing framework_
* [supertest](https://www.npmjs.com/package/supertest) _for REST testing_
* [chai](http://chaijs.com) _for assertions_

##TODO
* SSL support
* HTML response when SQL injection detected from browsers (GET requests)
* additional SQL injection patterns
* error handling -- unreachable host, HTTP method not supported, etc.
* support for PUT, HEAD, DELETE, OPTIONS
