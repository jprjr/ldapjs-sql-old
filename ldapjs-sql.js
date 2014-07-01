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
var users = {};
var groups = {};
var sql_connection;

// end global variables

// User constructor
function User(dn,attributes) { // {{{1
    this.dn = dn;
    this.attributes = attributes;
    this.userpassword = false;
    var _userpassword;
    if(this.attributes.userpassword !== undefined) { // {{{2
        this.userpassword = true;
        _userpassword = this.attributes.userpassword;
        delete this.attributes.userpassword;
        this.checkPassword = function(password) {
            var matches;
            matches = _userpassword.match(/^(\{.+\})/);
            if(matches === null) {
                // password stored in plaintext
                if(password !== _userpassword) {
                    return false;
                }
                return true;
            }
            else {
                var hashmethod = matches[1].replace('{','').replace('}','').toLowerCase();
                var passdata = _userpassword.replace(matches[1],'');
                if(hashmethod === 'sha') {
                    hashmethod = 'sha1'; // node seems to produce different results between sha and sha1
                }
                var hash = crypto.createHash(hashmethod).update(password).digest('base64');
                if(hash !== passdata) {
                    return false;
                }
                return true;
            }
            // Getting here shouldn't happen, this is a just-in-case
            return false;
        }

    } // }}}
    return this;
} // }}}

function loadUsers() { /// {{{1
    sql_connection.query(config.ldap.users.query, function(err, rows) {
        users = {};
        for(var row in rows) {
            var rdn =
              rows[row][config.ldap.users.sqlmapping[config.ldap.users.rdn]] + ','
              + 'ou='+config.ldap.users.ou + ','
              + config.ldap.basedn;
            var userkey = config.ldap.users.rdn + '=' + rdn;
            var attributes = {};
            for(var attr in config.ldap.users.sqlmapping) {
                if(rows[row][config.ldap.users.sqlmapping[attr]] !== undefined) {
                    attributes[attr.toLowerCase()] = rows[row][config.ldap.users.sqlmapping[attr]];
                }
            }
            for(var attr in config.ldap.users.staticmapping) {
                attributes[attr.toLowerCase()] = config.ldap.users.staticmapping[attr];
            }
            users[userkey] = new User(userkey,attributes);
        }
    });
} // }}}

function loadGroups() { // {{{1
    sql_connection.query(config.ldap.groups.query, function(err, rows) {
        groups = {};
        for(var row in rows) {
            var rdn = rows[row][config.ldap.groups.sqlmapping[config.ldap.groups.rdn]] + ',' + 'ou='+config.ldap.groups.ou + ',' + config.ldap.basedn;
            if(groups[rdn] === undefined) {
                groups[rdn] = {
                    dn: config.ldap.groups.rdn + '=' + rdn,
                    attributes: {},
                }
                for(var attr in config.ldap.groups.sqlmapping) {
                    if(rows[row][config.ldap.groups.sqlmapping[attr]] !== undefined) {
                        groups[rdn].attributes[attr.toLowerCase()] = rows[row][config.ldap.groups.sqlmapping[attr]];
                    }
                }
                for(var attr in config.ldap.groups.staticmapping) {
                    groups[rdn].attributes[attr.toLowerCase()] = config.ldap.groups.staticmapping[attr];
                }
            }
            for(var attr in config.ldap.groups.membermapping) {
                if(groups[rdn].attributes[attr.toLowerCase()] === undefined) {
                    groups[rdn].attributes[attr.toLowerCase()] = new Array();
                }

                var userdn = config.ldap.users.rdn
                             + '='
                             + rows[row][config.ldap.groups.membermapping[attr]]
                             + ',ou='+config.ldap.users.ou
                             + ','
                             + config.ldap.basedn;
                if(users[userdn] !== undefined) {
                    // user exists
                    groups[rdn].attributes[attr].push(userdn);
                    if(users[userdn].attributes['memberof'] === undefined) {
                        users[userdn].attributes['memberof'] = new Array();
                    }
                    users[userdn].attributes['memberof'].push(config.ldap.groups.rdn + '=' + rdn);
                }
            }
        }
    });
} // }}}

function handleDisconnect() { // {{{1
    sql_connection = Sql.createConnection( config.sql );

    sql_connection.connect(function(err) {
        if(err) {
            console.log("Error connecting to db: ", err);
            setTimeout(handleDisconnect, 2000);
        }
        else {
            loadUsers();
            loadGroups();
            setTimeout(function() {
                loadUsers();
                loadGroups();
            }, config.sql.timeout);
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
} // }}}

handleDisconnect();

function endRequest(req,res,next) { // {{{1
    res.end();
    return next();
} // }}}

function userSearch(req,res,next) { // {{{1
    var dn = req.connection.ldap.bindDN.toString();
    var userObj = users[dn];
    if(userObj === undefined) {
        return next(new Ldap.InsufficientAccessRightsError());
    }
    var ou_dn = 'ou=' + config.ldap.users.ou + ','
                + config.ldap.basedn;
    var ou = { dn: ou_dn,
               attributes: { ou: config.ldap.users.ou, objectclass: ['top','organizationalunit'], hasSubordinates: ['TRUE'] },
    };

    if( req.scope === 'sub' ||
          (req.scope === 'one' && req.dn.toString() === config.ldap.basedn) ||
          (req.scope === 'base' && req.dn.toString() === ou_dn ) ) {
        if(req.filter.matches(ou.attributes)) {
            res.send(ou);
        }
    }

    if( req.scope === 'sub' ||
          (req.scope === 'one' && req.dn.toString() === ou_dn)) {
        Object.keys(users).forEach(function(k) {
            if(req.filter.matches(users[k].attributes)) {
                res.send(users[k]);
            }
        });
    }
} // }}}

function groupSearch(req,res,next) { // {{{1
    var dn = req.connection.ldap.bindDN.toString();
    var userObj = users[dn];
    if(userObj === undefined) {
        return next(new Ldap.InsufficientAccessRightsError());
    }
    var ou_dn = 'ou='+config.ldap.groups.ou + ','
                + config.ldap.basedn;

    var ou = { dn: ou_dn,
               attributes: { ou: config.ldap.groups.ou, objectclass: ['top','organizationalunit'], hasSubordinates: ['TRUE']},
    };

    if( req.scope === 'sub' ||
          (req.scope === 'one' && req.dn.toString() === config.ldap.basedn) ||
          (req.scope === 'base' && req.dn.toString() === ou_dn ) ) {
        if(req.filter.matches(ou.attributes)) {
            res.send(ou);
        }
    }

    if( req.scope === 'sub' ||
          (req.scope === 'one' && req.dn.toString() === ou_dn)) {
        Object.keys(groups).forEach(function(k) {
            if(req.filter.matches(groups[k].attributes)) {
                res.send(groups[k]);
            }
        });
    }
} //}}}

var server_config = {};
if(config.ldap.ssl_cert !== undefined) {
    server_config.certificate = config.ldap.ssl_cert;
}
if(config.ldap.ssl_key !== undefined) {
    server_config.key = config.ldap.ssl_key;
}

var server = Ldap.createServer(server_config);
server.listen(config.ldap.port, function() {
    console.log('LDAP server listening at %s', server.url);
});


// bind
server.bind('ou='+config.ldap.users.ou +',' + config.ldap.basedn, function(req,res,next) { // {{{1
    var dn = req.dn.toString();
    var userObj = users[dn];
    if(userObj === undefined) {
        return next(new Ldap.InsufficientAccessRightsError());
    }

    if(! userObj.userpassword) {
        return next(new Ldap.NoSuchAttributeError('userpassword'));
    }

    if(! userObj.checkPassword(req.credentials.toString()) ) {
        return next(new Ldap.InvalidCredentialsError());
    }

    res.end();
    return next();
}); // }}}


// Group Search
server.search('ou='+config.ldap.groups.ou +','+config.ldap.basedn, function(req,res,next) { // {{{1
    groupSearch(req,res,next);
    endRequest(req,res,next);
}); // }}}

// User Search
server.search('ou='+config.ldap.users.ou +','+config.ldap.basedn, function(req,res,next) { // {{{1
    userSearch(req,res,next);
    endRequest(req,res,next);
}); // }}}

// Root Search
server.search(config.ldap.basedn,  function(req,res,next) { // {{{1
    var dn = req.connection.ldap.bindDN.toString();
    var userObj = users[dn];
    if(userObj === undefined) {
        return next(new Ldap.InsufficientAccessRightsError());
    }

    if(req.scope === 'base' || req.scope == 'sub') {
        var rootdn = { dn: config.ldap.basedn,
                       attributes: { dc:config.ldap.basedc, objectclass: ['dcObject','organization'], hasSubordinates: ['TRUE']},
        };
        if(req.filter.matches(rootdn.attributes)) {
            res.send(rootdn);
        }
    }
    else { // implies scope == 'one'

    }
    // users
    userSearch(req,res,next);
    groupSearch(req,res,next);

    endRequest(req,res,next);
}); // }}}

