
var util = require('util');

var passport = require('passport-strategy');

var mauthcrypto = require('mauth-crypto');


var defaultOptions = {
	getCredentials: function(req, callback) {
		callback(undefined, {
			'user':req.body.username,
			'secret':req.body.secret
		});
	},
	getUserDetails: function(user, callback) {
		callback(new Error('getUserDetails not implemented'));
		// {
		// 	user: 'userObject',
		// 	externalSalt: 'salt',
		// 	internalSalt: 'salt',
		// 	hash: 'hash',
		// 	info: 'optional info'
		// }
	},
	salt: mauthcrypto.salt,
	hash: mauthcrypto.hash,
	getFakeSalt: function(callback) {
		if (this.fakeSalt) {
			callback(undefined, this.fakeSalt);
		} else {
			console.log('WARNING: You have not chosen a standard fake salt!');
			var _this = this;
			this.salt(function(err, salt) {
				if (err) {
					callback(err);
				} else {
					_this.fakeSalt = salt;
					callback(undefined, salt);
				}
			});
		}
	}
};

function MauthStrategy(options) {
	passport.Strategy.call(this);
	this.name = 'mauth';
	this._options = Object.assign({}, defaultOptions, options);
}
util.inherits(MauthStrategy, passport.Strategy);

MauthStrategy.prototype.authenticate = function(req, optionOverrides) {
	var options = Object.assign({}, this._options, optionOverrides);

	try {
		var _this = this;
		options.getCredentials(req, function(err, credentials) {
			if (!err && (!credentials || !credentials.user || !credentials.secret)) {
				err = new Error('');
			}
			if (err) {
				_this.fail(err);
			} else {
				options.getUserDetails(credentials.user, function(err, userDetails) {
					if (!err && (!userDetails || !userDetails.user || !userDetails.internalSalt || !userDetails.hash)) {
						err = new Error('');
					}
					if (err) {
						_this.fail(err);
					} else {
						options.hash(credentials.secret, userDetails.internalSalt, function(err, hash) {
							if (!err && hash != userDetails.hash) {
								err = new Error('');
							}
							if (err) {
								_this.fail(err);
							} else {
								_this.success(userDetails.user, userDetails.info);
							}
						});
					}
				});
			}
		});
	} catch(err) {
		this.error(err);
	}
};

MauthStrategy.prototype.getRegisterDetails = function(user, secret, callback, optionOverrides) {
	var options = Object.assign({}, this._options, optionOverrides);

	options.salt(function(err, salt) {
		if (err) {
			callback(err);
		} else {
			options.hash(secret, salt, function(err, hash) {
				if (err) {
					callback(err);
				} else {
					callback(undefined, {
						'internalSalt':salt,
						'hash':hash
					});
				}
			});
		}
	});
};

MauthStrategy.prototype.getExternalSalt = function(user, callback, optionOverrides) {
	var options = Object.assign({}, this._options, optionOverrides);

	options.getUserDetails(user, function(err, userDetails) {
		if (err || !userDetails || !userDetails.externalSalt) {
			options.getFakeSalt(function(err, salt) {
				options.hash(user, salt, callback);
			});
		} else {
			callback(undefined, userDetails.externalSalt);
		}
	});
};

MauthStrategy.prototype.externalSaltHandler = function(optionOverrides)  {
	var _this = this;

	var options = Object.assign({}, this._options, optionOverrides);

	return function(req, res, next) {
		options.getCredentials(req, function(err, credentials) {
			if (err) {
				next(err);
			} else {
				_this.getExternalSalt(credentials.user, function(err, salt) {
					res.json({
						'salt':salt
					});
				}, optionOverrides);
			}
		});
	};
};


module.exports = MauthStrategy;
