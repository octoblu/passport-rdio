/**
 * Module dependencies.
 */
var util = require('util')
  , querystring = require('querystring')
  , OAuth2Strategy = require('passport-oauth').OAuth2Strategy
  , InternalOAuthError = require('passport-oauth').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * The Rdio authentication strategy authenticates requests by delegating to Rdio
 * using the OAuth2 protocol.
 *
 * Applications must supply a `verify` callback which accepts a `token`,
 * `tokenSecret` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      identifies client to Rdio
 *   - `clientSecret`  secret used to establish ownership of the consumer key
 *   - `callbackURL`   URL to which Rdio will redirect the user after obtaining authorization
     - `scope`         [Optional] An array of named scopes containing:
 *                        "shared_playstate" if you want to use the Rdio JavaScript API to
 *                        remote control the official Rdio applications
 *
 * Examples:
 *
 *     passport.use(new RdioStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
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
  }

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Retrieve user profile from Rdio.
 *
 * This function constructs a normalized profile, with the following properties:
 *   - `provider`    always set to 'rdio'
 *   - `id`          users Rdio ID
 *   - `displayName` users full name
 *   - `name`        Object with familyName and givenName keys
 *   - `emails`      An array containing users email addresses
 *   - `username`    Rdio username
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  var headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
  };

  var postData = querystring.stringify({method: 'currentUser', extras: 'email, vanityName'});

  this._oauth2._request('POST', 'https://services.rdio.com/api/1', headers, postData, accessToken, function(err, body, res) {
    if (err) {
      return done(new InternalOAuthError('failed to fetch user profile', err));
    }

    try {
      var json = JSON.parse(body);

      if (json.status == 'error') {
        return done(new InternalOAuthError('failed to fetch user profile', json.message));
      }
      var profile = {
        provider: 'rdio',
        id: json.result.key,
        username: json.result.username,
        emails: [json.result.email],
        displayName: json.result.firstName + ' ' + json.result.lastName,
        name: { familyName: json.result.lastName,
                givenName: json.result.firstName },
        _raw: body,
        _json: json,
      };
      console.log('profile', profile);
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
