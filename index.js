
var MauthStrategy = require('./strategy');


function Mauth() {
	this.strategies = {};
}

Mauth.prototype.strategy = function(name, options) {
	if (!name && !options) {
		name = 'mauth';
	}
	if (name && !options && !(typeof name === 'string' || name instanceof String)) {
		options = name;
		name = 'mauth';
	}
	if (options) {
		var strategy = new MauthStrategy(options);
		strategy.name = name;
		this.strategies[name] = strategy;
	}
	return this.strategies[name];
};


module.exports = new Mauth();

module.exports.MauthStrategy = MauthStrategy;
