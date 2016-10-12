
'use strict';

var config = {};

config.proxy_port = 8080;

config.target_host = "demo8978876.mockable.io"; // demo8978876.mockable.io/default responds with JSON for GET, POST, PUT, and DELETE
config.target_port = 80; // default to HTTP port 80. if your target uses SSL, this should be changed, most likely to 443
config.force_ssl = false; // set this true if your target uses SSL, but uses a port other than the default HTTPS port 443

module.exports = config;