#!/usr/bin/env node

var Ldap = require('ldapjs');
var Sql = require('mysql');
var crypto = require('crypto');
var argv = require('minimist')(process.argv.slice(2));

if(! ("config" in argv)) {
    console.log("I need an argument passed to --config");
    process.exit(1);
}

var config = require(argv.config);

var sql_connection;

function handleDisconnect() {
    sql_connection = Sql.createConnection( config.sql );

    sql_connection.connect(function(err) {
        if(err) {
            console.log("Error connecting to db: ", err);
            setTimeout(handleDisconnect, 2000);
        }
    });

    sql_connection.on('error', function(err) {
        console.log("DB error: ", err);
        if(err.code === 'PROTOCOL_CONNECTION_LOST') {
            handleDisconnect();
        } else {
            throw err;
        }
    });
}

handleDisconnect();

function loadUsers(req, res, next) {
    sql_connection.query(config.ldap.users.query, function(err, rows) {
        if(err) {
            return next(new Ldap.OperationsError(err.message));
        }
        req.users = {};
        for(var row in rows) {
            var rdn = rows[row][config.ldap.users.sqlmapping[config.ldap.users.rdn]] + ',' + config.ldap.users.ou + ',' + config.ldap.basedn;
            var userkey = config.ldap.users.rdn + '=' + rdn;
            req.users[userkey] = {
                dn: userkey,
                attributes: {},
            }
            for(var attr in config.ldap.users.sqlmapping) {
                req.users[userkey].attributes[attr] = rows[row][config.ldap.users.sqlmapping[attr]];
            }
            for(var attr in config.ldap.users.staticmapping) {
                req.users[userkey].attributes[attr] = config.ldap.users.staticmapping[attr];
            }
        }
        return next();
    });
}

function loadGroups(req, res, next) {
    sql_connection.query(config.ldap.groups.query, function(err, rows) {
        if(err) {
            return next(new Ldap.Operationserror(err.message));
        }
        req.groups = {};
        for(var row in rows) {
            var rdn = rows[row][config.ldap.groups.sqlmapping[config.ldap.groups.rdn]];
            if(req.groups[rdn] === undefined) {
                req.groups[rdn] = {
                    dn: config.ldap.groups.rdn + '=' + rdn + ',' + config.ldap.groups.ou + ',' + config.ldap.basedn,
                    attributes: {},
                }
                for(var attr in config.ldap.groups.sqlmapping) {
                    req.groups[rdn].attributes[attr] = rows[row][config.ldap.groups.sqlmapping[attr]];
                }
                for(var attr in config.ldap.groups.staticmapping) {
                    req.groups[rdn].attributes[attr] = config.ldap.groups.staticmapping[attr];
                }
            }
            for(var attr in config.ldap.groups.membermapping) {
                if(req.groups[rdn].attributes[attr] === undefined) {
                    req.groups[rdn].attributes[attr] = new Array();
                }
                req.groups[rdn].attributes[attr].push(rows[row][config.ldap.groups.membermapping[attr]]);
            }
        }
        return next();
    });
}



var preUsers = [loadUsers];
var preGroups = [loadGroups];

var server = Ldap.createServer();
server.listen(1389, function() {
    console.log('LDAP server listening at %s', server.url);
});


server.bind(config.ldap.users.ou +',' + config.ldap.basedn, preUsers, function(req,res,next) {
    var dn = req.dn.toString();
    var userObj = req.users[dn];
    if(userObj === undefined) {
        return next(new Ldap.NoSuchObjectError(dn));
    }

    if(userObj.attributes.userPassword === undefined) {
        return next(new Ldap.NoSuchAttributeError('userPassword'));
    }

    var matches;
    matches = userObj.attributes.userPassword.match(/^(\{.+\})/);
    if(matches === null) {
        // password stored in plaintext
        if(req.credentials.toString() !== userObj.attributes.userPassword) {
            return next(new Ldap.InvalidCredentialsError());
        }
    }
    else {
        var hashmethod = matches[1].replace('{','').replace('}','').toLowerCase();
        var passdata = userObj.attributes.userPassword.replace(matches[1],'');
        if(hashmethod === 'sha') {
            hashmethod = 'sha1'; // node seems to produce different results between sha and sha1
        }
        var hash = crypto.createHash(hashmethod).update(req.credentials.toString()).digest('base64');
        if(hash !== passdata) {
            return next(new Ldap.InvalidCredentialsError());
        }
    }

    res.end();
    return next();
});


server.search(config.ldap.users.ou +','+config.ldap.basedn, preUsers, function(req,res,next) {
    if(req.scope == 'sub') {
        var ou = { dn: config.ldap.users.ou + ',' + config.ldap.basedn,
                   attributes: { objectclass: ['top','organizationalUnit'], hasSubordinates: ['TRUE'] },
                 };
        if(req.filter.matches(ou.attributes)) {
            res.send(ou);
        }
    }

    Object.keys(req.users).forEach(function(k) {
        if(req.filter.matches(req.users[k].attributes)) {
            res.send(req.users[k]);
        }
    });

    res.end();
    return next();
});

server.search(config.ldap.groups.ou +','+config.ldap.basedn, preGroups, function(req,res,next) {
    if(req.scope == 'sub') {
        var ou = { dn: config.ldap.groups.ou + ',' + config.ldap.basedn,
                   attributes: { objectclass: ['top','organizationalUnit'], hasSubordinates: ['TRUE'] },
                 };
        if(req.filter.matches(ou.attributes)) {
            res.send(ou);
        }
    }

    Object.keys(req.groups).forEach(function(k) {
        if(req.filter.matches(req.groups[k].attributes)) {
            res.send(req.groups[k]);
        }
    });

    res.end();
    return next();
});
