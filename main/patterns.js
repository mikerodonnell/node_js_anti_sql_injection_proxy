
'use strict';

var patterns = [
    {
        // whitespace followed by an equality of on or more characters to itself, like 1=1, 451=451, or 'test'='test'
        "regex": /\s(.+)=\1+/,
        "description": "Equality expression. (ex. 1=1)"
    },
    {
        // whitespace followed by a SQL command word, like DROP
        "regex": /\s(SELECT|DROP|UPDATE|CREATE|INSERT|ALTER|UNION|MERGE)/i,
        "description": "SQL query keyword. (ex. DROP)"
    },
    {
        // SQL function related to the DB username, DB name, server name, etc
        "regex": /(CURRENT_USER|CURRENT_USER\(\)|USER\(\))/i,
        "description": "SQL function. (ex. CURRENT_USER())"
    },
    {
        // same as above, but enforcing case sensitivity for this MS SQL specific case, to avoid false positives
        "regex": /(USER)/,
        "description": "MS SQL function. (ex. USER)"
    }
];

module.exports = patterns;