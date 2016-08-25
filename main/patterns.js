
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
        "description": "SQL command. (ex. DROP)"
    }
];

module.exports = patterns;