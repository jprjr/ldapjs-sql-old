#ldapjs-sql

This is a small utility for bridging a MySQL database full of users to LDAP. The whole thing is pretty hacky - I just wanted to get ejabberd up-and-running with an already-existing db of users.

You can run this program like `node ldapjs-sql.js --config /path/to/config`

Your config file needs to be a javascript file that exports a module. See `config.exampe.js` for an example file with comments on what everything does.

The config file basically defines what sql queries to use to populate users and groups. The users that get generated should work for authenticating most apps. The groups functionality is really just for ejabberd shared rosters, I don't think it's really useful for anything else.

I assume your passwords are stored as `{HASH}base64data`, so the password `test` hashed with SHA1 would be `{SHA}qUqP5cyxm6YcTAhz05Hph5gvu9M=`. If your password does not have `{HASH}` at the beginning I assume it's plaintext.

Also, every bind request repulls all the users, so I don't think this is really scalable or anything. I would love it if somebody else reimplemented all this in a scalable way, but it's fast-enough for my purposes.
