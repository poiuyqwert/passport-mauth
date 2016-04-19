## Back End
# Installation
	npm install passport-mauth
# Initialization
	var passport = require('passport');
	var mauth = require('passport-mauth');
	
	// Initialize global mauth strategy
	mauth.strategy({
		// You should use a constant secure fakeSalt (see fakeSalt section)
		fakeSalt: config.fakeSalt,
		// You must provide a function to get user details
		getUserDetails: function(username, callback) {
			// Lookup user
			lookupUserByUsername(username)
			.then(function(user) {
				var userDetails;
				if (user) {
					userDetails = {
						user: user,
						externalSalt: user.externalSalt,
						internalSalt: user.internalSalt,
						hash: user.hash
					};
				}
				callback(undefined, userDetails);
			})
			.catch(function(err) {
				callback(err);
			});
		}
	});
	
	passport.use(mauth.strategy());

# Registration Endpoint
	var mauth = require('passport-mauth');
	
	router.post('/register', function(req, res, next) {
		var username = req.body.username;
		var secret = req.body.secret;
		var salt = req.body.salt;
		lookupUserByUsername(username)
		.then(function(user) {
			if (user) {
				throw new Error('user exists');
			}
			return new Promise(function(resolve, reject) {
				mauth.strategy().getRegisterDetails(username, secret, function(err, registerDetails) {
					if (err) {
						reject(err);
					} else {
						resolve(registerDetails);
					}
				});
			});
		})
		.then(function(registerDetails) {
			return registerNewUser({
				username: username,
				externalSalt: salt,
				internalSalt: registerDetails.internalSalt,
				hash: registerDetails.hash
			});
		})
		.then(function(user) {
			return new Promise(function(resolve, reject) {
				req.login(user, function(err) {
					if (err) {
						reject(err);
					} else {
						resolve(user);
					}
				});
			});
		})
		.then(function(user) {
			res.redirect('/profile/' + user.id);
		})
		.catch(function(err) {
			next(err);
		});
	}

# Login Endpoints
	var mauth = require('passport-mauth');
	
	router.post('/getSalt', mauth.strategy().externalSaltHandler());
	
	router.post('/login', passport.authenticate('mauth'));

## Front End
Using `mauth-crypto` for front end encryption as well.
# Instal mauth-crypto
	npm install mauth-crypto --save
# Registration
	var mauth = require('mauth-crypto');
	
	$('#register-submit').click(function(event) {
		var username = $('#register-username').val();
		var password = $('#register-password').val();
		if (password === $('#register-password-confirm').val()) {
			mauth.salt(function(err, salt) {
				if (!err) {
					mauth.hash(password, salt, function(err, hash) {
						$.ajax({
							method: 'POST',
							url: '/register',
							data: {
								username: username,
								salt: salt,
								secret: hash
							},
							dataType: 'json'
						});
					}, 1000);
				}
			});
		}
	});

# Login
	var mauth = require('mauth-crypto');
	
	$('#login-submit').click(function(event) {
		var username = $('#login-username').val();
		var password = $('#login-password').val();
		$.ajax({
			method: 'POST',
			url: '/getSalt',
			data: {
				username: username
			},
			dataType: 'json'
		})
		.done(function(response) {
			mauth.hash(password, response.salt, function(err, hash) {
				$.ajax({
					method: 'POST',
					url: '/user/login',
					data: {
						username: username,
						secret: hash
					},
					dataType: 'json'
				});
			}, 1000);
		});
	});