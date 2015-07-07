/**
 * Module dependencies.
 */
var util = require('util')
  , OAuth2Strategy = require('passport-oauth2')
  , InternalOAuthError = require('passport-oauth2').InternalOAuthError
  , querystring = require('querystring');

/**
 * `Strategy` constructor.
 *
 * The Rdio authentication strategy authenticates requests by delegating to
 * Rdio using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Rdio application's Client ID
 *   - `clientSecret`  your Rdio application's Client Secret
 *   - `callbackURL`   URL to which Rdio will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new CitrixStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/rdio/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
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
  options.name = options.name || 'rdio';
  options.profileURL = options.profileURL || 'https://services.rdio.com/api/1/';
  options.authorizationURL = options.authorizationURL || 'https://www.rdio.com/oauth2/authorize';
  options.tokenURL = options.tokenURL || 'https://services.rdio.com/oauth2/token';
  options.customHeaders = options.customHeaders || {};

  OAuth2Strategy.call(this, options, verify);
  this.name = options.name;
  this.profileURL = options.profileURL;
  this._oauth2.useAuthorizationHeaderforGET(true);

  var generateAuthHeader = function(clientId, clientSecret) {
    var token = new Buffer(clientId + ':' + clientSecret).toString("base64");
    return 'Basic ' + token;
  };
  this.generateAuthHeader = generateAuthHeader;
  this._oauth2.getOAuthAccessToken = function(code, params, callback) {
    var params= params || {};
    var codeParam = (params.grant_type === 'refresh_token') ? 'refresh_token' : 'code';
    params[codeParam] = code;
    var requestBody = querystring.stringify(params);

    var requestHeader = {};
    requestHeader['Authorization'] = generateAuthHeader(this._clientId, this._clientSecret);
    requestHeader['Content-Type'] = 'application/x-www-form-urlencoded';

    this._request("POST", this._getAccessTokenUrl(), requestHeader, requestBody, null, function(error, data, response) {
      if( error )  callback(error);
      else {
        var results;
        try {
          // As of http://tools.ietf.org/html/draft-ietf-oauth-v2-07
          // responses should be in JSON
          results= JSON.parse( data );
        }
        catch(e) {
          // .... However both Facebook + Github currently use rev05 of the spec
          // and neither seem to specify a content-type correctly in their response headers :(
          // clients of these services will suffer a *minor* performance cost of the exception
          // being thrown
          results= querystring.parse( data );
        }
        var access_token= results["access_token"];
        var refresh_token= results["refresh_token"];
        delete results["refresh_token"];
        callback(null, access_token, refresh_token, results); // callback results =-=
      }
    });
  }
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
 *   - `provider`         always set to `rdio-auth-service`
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  var userProfileURL = this.profileURL;
  var authHeader = {
    'Authorization': this._oauth2.buildAuthHeader(accessToken),
    'Content-Type': 'application/x-www-form-urlencoded'
  };

  var bodyParams = {
    method : 'currentUser'
  };

  this._oauth2._request('POST', userProfileURL, authHeader, querystring.stringify(bodyParams), accessToken, function (err, body, res) {
    var json;

    if (err) {
      return done(new InternalOAuthError('Failed to fetch user profile', err));
    }

    try {
      json = JSON.parse(body);
    } catch (ex) {
      return done(new Error('Failed to parse user profile'));
    }

    var profile = json;
    profile.provider  = 'rdio';
    profile._raw = body;
    profile._json = json;

    done(null, profile);
  });
}

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
