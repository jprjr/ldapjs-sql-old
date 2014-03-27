var fs = require('fs');
var config = {};

config.sql  = {};
config.ldap = {};

// config.sql gets passed directly to mysql.createConnection
// see https://github.com/felixge/node-mysql#connection-options
config.sql.host       = 'sql-host';
config.sql.port       = '3306';
config.sql.user       = 'someusername';
config.sql.password   = 'somepassword';
config.sql.database   = 'mydatabaseofstuff';


// config.ldap.timeout sets how often to refresh
// the users and groups from the sql database
// This value is in milliseconds
config.ldap.timeout = 1000 * 60 * 5; // 5 minutes
// basedn will be appended to all other objects
// ie - a users full rdn will wind up being
//   config.ldap.users.rdn +
//   config.ldap.users.ou +
//   config.ldap.basedn
config.ldap.basedn = 'dc=example,dc=com';

// basedc is really only used against a root search
config.ldap.basedc = 'example';

config.ldap.users = {};
config.ldap.users.ou    = 'ou=users';

// attributes that won't be pulled from the sql db
config.ldap.users.staticmapping = {
    'objectclass': 'inetOrgPerson',
};
// Remember to check what attributes your objectclass
// needs in order to be valid!

// whatever you use for rdn *must* have a mapping
// under sqlmapping!
config.ldap.users.rdn   = 'cn';
config.ldap.users.sqlmapping = {
    'cn'              : 'full_name',
    'uid'             : 'username',
    'givenName'       : 'first_name',
    'sn'              : 'last_name',
    'userPassword'    : 'password',
};

config.ldap.users.sqlfile = "users.sql";


// groups follows a similar setup to users, except membermapping
config.ldap.groups = {};
config.ldap.groups.ou  = 'ou=groups';

config.ldap.groups.staticmapping = {
    'objectclass' : ['groupOfURLs','top'],
};

config.ldap.groups.rdn = 'cn';
config.ldap.groups.sqlmapping = {
    'cn'          : 'name',
    'description' : 'name',
};
config.ldap.groups.membermapping = {
    'memberURL'   : 'username',
};

config.ldap.groups.sqlfile = "groups.sql";

// don't edit this
config.ldap.users.query = fs.readFileSync(config.ldap.users.sqlfile).toString();
config.ldap.groups.query = fs.readFileSync(config.ldap.groups.sqlfile).toString();

module.exports = config;
