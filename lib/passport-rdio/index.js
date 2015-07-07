/**
 * Module dependencies.
 */
var Strategy = require('./oauth2strategy');


/**
 * Framework version.
 */
require('pkginfo')(module, 'version');

/**
 * Expose constructors.
 */
exports.Strategy = Strategy;
