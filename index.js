var settings = require('./config/config.json');

var bodyParser = require('body-parser');
var jwt = require('jwt-simple');
var moment = require('moment');
var LdapAuth = require('ldapauth-fork');
var Promise  = require('promise');
var ldapjs = require('ldapjs')
app = require('express')();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(require('cors')());



//CREATE USER
// const ldapClient = ldapjs.createClient(ldapOptions);



var addUser = function addUser(userId, givenName, familyName, password) {
    return new Promise(function (resolve, reject) {

        console.log(userId,givenName,familyName,password);
        // 1
        var ldapClient = ldapjs.createClient(settings.ldap);

        // 2
        ldapClient.bind("admin", "secret", function (err) {
            var _newUser;

            if (err) return reject(err);

            var newUser = (_newUser = {
                givenName: 'none',
                uid: userId
            },  _defineProperty(_newUser, "givenName", givenName),
                _defineProperty(_newUser, "familyName", familyName),
                _defineProperty(_newUser, "cn", userId),
                _defineProperty(_newUser, "userPassword", password),
                _defineProperty(_newUser, "objectClass", ["person", "organizationalPerson", "inetOrgPerson"]),
                _defineProperty(_newUser, "pwdPolicySubentry", ldapConfig.pwdPolicySubentry), _newUser);

            // 3
            ldapClient.add('cn=' + userId + ',' + ldapConfig.domain, newUser, function (err, response) {
                if (err) return reject(err);
                return resolve(response);
            });
        });
    });
};

app.get("/register",function (req,res) {
    addUser('abc','abc','abc','abc')
        .then(function (resp) {
            console.log(resp);
        })
});


// -------------------



var auth = new LdapAuth(settings.ldap);


app.set('jwtTokenSecret', settings.jwt.secret);

var authenticate = function (username, password) {
	return new Promise(function (resolve, reject) {
		auth.authenticate(username, password, function (err, user) {
			if(err)
				reject(err);
			else if (!user)
				reject();
			else
				resolve(user);
		});
	});
};

app.post('/authenticate', function (req, res) {
	if(req.body.username && req.body.password) {
		authenticate(req.body.username, req.body.password)
			.then(function(user) {
				var expires = parseInt(moment().add(2, 'days').format("X"));
				var token = jwt.encode({
					exp: expires,
					user_name: user.cn,
					full_name: user.cn + " "+user.sn,
					mail: user.mail
				}, app.get('jwtTokenSecret'));
				// res.json(token);
				res.json({token: token, full_name: user.cn});
			})
			.catch(function (err) {
				// Ldap reconnect config needs to be set to true to reliably
				// land in this catch when the connection to the ldap server goes away.
				// REF: https://github.com/vesse/node-ldapauth-fork/issues/23#issuecomment-154487871

				console.log(err);

				if (err.name === 'InvalidCredentialsError' || (typeof err === 'string' && err.match(/no such user/i)) ) {
					res.status(401).send({ error: 'Wrong user or password'});
				} else {
					// ldapauth-fork or underlying connections may be in an unusable state.
					// Reconnect option does re-establish the connections, but will not
					// re-bind. Create a new instance of LdapAuth.
					// REF: https://github.com/vesse/node-ldapauth-fork/issues/23
					// REF: https://github.com/mcavage/node-ldapjs/issues/318

					res.status(500).send({ error: 'Unexpected Error'});
					auth = new LdapAuth(settings.ldap);
				}

			});
		} else {
			res.status(400).send({error: 'No username or password supplied'});
		}
});

app.get('/verify', function (req, res) {
	var token = req.query.token;
	if (token) {
		try {
			var decoded = jwt.decode(token, app.get('jwtTokenSecret'));

			if (decoded.exp <= parseInt(moment().format("X"))) {
				res.status(400).send({ error: 'Access token has expired'});
			} else {
				res.json({
					user_name: decoded.user_name,
					full_name: decoded.full_name,
					mail: decoded.mail
				});
			}
		} catch (err) {
			res.status(500).send({ error: 'Access token could not be decoded'});
		}
	} else {
		res.status(400).send({ error: 'Access token is missing'});
	}
});


var port = (process.env.PORT || 3000);
app.listen(port, function() {
	console.log('Listening on port: ' + port);

	if (typeof settings.ldap.reconnect === 'undefined' || settings.ldap.reconnect === null || settings.ldap.reconnect === false) {
		console.warn('WARN: This service may become unresponsive when ldap reconnect is not configured.')
	}
});
