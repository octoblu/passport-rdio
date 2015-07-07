/**
 * Module dependencies.
 */
var util = require('util')
  , OAuth2Strategy = require('passport-oauth').OAuth2Strategy
  , InternalOAuthError = require('passport-oauth').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * The Rdio authentication strategy authenticates requests by delegating to Rdio
 * using the OAuth protocol.
 *
 * Applications must supply a `verify` callback which accepts a `token`,
 * `tokenSecret` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `consumerKey`     identifies client to Rdio
 *   - `consumerSecret`  secret used to establish ownership of the consumer key
 *   - `callbackURL`     URL to which Rdio will redirect the user after obtaining authorization
 *
 * Examples:
 *
 *     passport.use(new RdioStrategy({
 *         consumerKey: '123-456-789',
 *         consumerSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/rdio/callback'
 *       },
 *       function(token, tokenSecret, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://www.rdio.com/oauth2/authorize'
  options.tokenURL = options.tokenURL || 'https://services.rdio.com/oauth2/token';

  OAuth2Strategy.call(this, options, verify);
  this.name = 'rdio';
  this._userProfileURL = options.userProfileURL || 'https://api.github.com/user';
  this._oauth2.setAuthMethod('OAuth');
  this._oauth2.useAuthorizationHeaderforGET(true);
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Retrieve user profile from Rdio.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `id`
 *   - `displayName`
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  //this._oauth2.get('http://api.rdio.com/1/', token, tokenSecret, { method: 'currentUser' }, function (err, body, res) {
  this._oauth2.get(this._userProfileURL, accessTokentoken, tokenSecret, { method: 'currentUser' }, function (err, body, res) {
    if (err) {
      return done(new InternalOAuthError('failed to fetch user profile', err)); }

    try {
      var json = JSON.parse(body);

      var profile = { provider: 'rdio' };
      profile.id = json.result.key;
      profile.displayName = json.result.firstName + ' ' + json.result.lastName;
      profile.name = { familyName: json.result.lastName,
                       givenName: json.result.firstName };

      profile._raw = body;
      profile._json = json;

      done(null, profile);
    } catch(e) {
      done(e);
    }
  });
}


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
