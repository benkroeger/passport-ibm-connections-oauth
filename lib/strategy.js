'use strict';

/* eslint-disable no-underscore-dangle */
// node core modules
const util = require('util');
const url = require('url');

// 3rd party modules
const OAuth2Strategy = require('passport-oauth2').Strategy;
const uid = require('uid2');

// internal modules
const Profile = require('./profile');
const utils = require('./utils');
const InternalOAuthError = require('passport-oauth2').InternalOAuthError;
// const AuthorizationError = require('./errors/authorizationerror');

/**
 * `Strategy` constructor.
 *
 * The IBM Connections authentication strategy authenticates requests by delegating to
 * IBM Connections using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` [optional `params`] and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 * If the `verify` callback takes the `params` parameter, it will receive all parameters
 * that the oAuth provider sent along with `accessToken` and `refreshToken`
 *
 * Options:
 *   - `clientID`      your IBM Connections application's App ID
 *   - `clientSecret`  your IBM Connections application's App Secret
 *   - `callbackURL`   URL to which IBM Connections will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new IBMConnectionsStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/ibm-connections/callback'
 *       },
 *       function(accessToken, refreshToken, params, profile, done) {
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
function Strategy(params = {}, verify) {
  // authorizationURL
  // callbackURL
  // clientID
  // clientSecret
  // customHeaders
  // passReqToCallback
  // proxy
  // scope
  // scopeSeparator
  // sessionKey
  // skipUserProfile
  // state
  // store
  // tokenURL

  const hostname = (() => {
    const result = params.host || params.hostname;
    if (!result) {
      throw new TypeError('IBMConnectionsOAuth requires a hostname');
    }

    return result;
  })();

  const authorizationURL = (() => {
    if (params.authorizationURL) {
      return params.authorizationURL;
    }

    const { authorizationPath = '/manage/oauth2/authorize' } = params;

    return url.resolve(`https://${hostname}`, authorizationPath);
  })();

  const tokenURL = (() => {
    if (params.tokenURL) {
      return params.tokenURL;
    }

    const { tokenPath = '/manage/oauth2/token' } = params;

    return url.resolve(`https://${hostname}`, tokenPath);
  })();

  const options = Object.assign({}, params, { authorizationURL, tokenURL });
  OAuth2Strategy.call(this, options, verify);
  this.name = 'ibm-connections-oauth';
  this._oauth2.useAuthorizationHeaderforGET(true);
  this._clientSecret = options.clientSecret;
  this._profileURL = (() => {
    if (params.profileURL) {
      return params.profileURL;
    }

    const { profilePath = '/connections/opensocial/oauth/rest/people/@me/@self' } = params;
    return url.resolve(`https://${hostname}`, profilePath);
  })();

  // IBM Connections Cloud doesn't support "scope"
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Authenticate request by delegating to IBM Connections using OAuth 2.0.
 *
 * @param {Object} req
 * @api protected
 */
// Strategy.prototype.authenticate = function(req, options) {
//   OAuth2Strategy.prototype.authenticate.call(this, req, options);
// };

Strategy.prototype.authenticate = function authenticate(req, options = {}) {
  const self = this;
  const key = self._key;

  if (req.query && req.query.oauth_error) {
    this.fail(req.query, 403);
    return;
  }

  let callbackURL = options.callbackURL || this._callbackURL;
  if (callbackURL) {
    const parsed = url.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(utils.originalURL(req, {
        proxy: this._trustProxy,
      }), callbackURL);
    }
  }

  if (req.query && req.query.code) {
    const code = req.query.code;

    if (this._state) {
      if (!req.session) {
        this.error(new Error('OAuth2Strategy requires session support when using state. Did you forget app.use(express.session(...))?'));
        return;
      }

      if (!req.session[key]) {
        this.fail({ message: 'Unable to verify authorization request state.' }, 403);
        return;
      }
      const state = req.session[key].state;
      if (!state) {
        this.fail({ message: 'Unable to verify authorization request state.' }, 403);
        return;
      }

      delete req.session[key].state;
      if (Object.keys(req.session[key]).length === 0) {
        delete req.session[key];
      }

      if (state !== req.query.state) {
        this.fail({ message: 'Invalid authorization request state.' }, 403);
        return;
      }
    }

    const params = this.tokenParams(options);
    params.grant_type = 'authorization_code';
    params.callback_uri = callbackURL;

    this._oauth2.getOAuthAccessToken(code, params, (err, accessToken, refreshToken, params) => {
      if (err) {
        self.error(self._createOAuthError('Failed to obtain access token', err));
        return;
      }

      self._loadUserProfile(accessToken, (loadUserProfileError, profile, setCookies) => {
        const arity = self._verify.length;
        if (loadUserProfileError) {
          self.error(loadUserProfileError);
          return;
        }

        function verified(verifiedError, user, info) {
          if (verifiedError) {
            self.error(verifiedError);
            return;
          }
          if (!user) {
            self.fail(info);
            return;
          }
          self.success(user, info);
        }

        try {
          if (self._passReqToCallback) {
            if (arity === 7) {
              self._verify(req, accessToken, refreshToken, params, profile, setCookies, verified);
            } else if (arity === 6) {
              self._verify(req, accessToken, refreshToken, params, profile, verified);
            } else { // arity == 5
              self._verify(req, accessToken, refreshToken, profile, verified);
            }
          } else if (arity === 6) {
            self._verify(accessToken, refreshToken, params, profile, setCookies, verified);
          } else if (arity === 5) {
            self._verify(accessToken, refreshToken, params, profile, verified);
          } else { // arity == 4
            self._verify(accessToken, refreshToken, profile, verified);
          }
        } catch (ex) {
          self.error(ex);
        }
      });
    });
  } else {
    const params = this.authorizationParams(options);
    params.response_type = 'code';
    params.callback_uri = callbackURL;

    let scope = options.scope || this._scope;
    if (scope) {
      if (Array.isArray(scope)) {
        scope = scope.join(this._scopeSeparator);
      }
      params.scope = scope;
    }

    if (!this._state) {
      // when strategy state mgmt is disabled, use externally provided state (if any) or generate a random value
      params.state = options.state || uid(24);
    } else {
      if (!req.session) {
        this.error(new Error('OAuth2Strategy requires session support when using state. Did you forget app.use(express.session(...))?'));
        return;
      }

      if (!req.session[key]) {
        req.session[key] = {};
      }

      const state = uid(24);
      req.session[key].state = state;
      params.state = state;
    }

    const location = this._oauth2.getAuthorizeUrl(params);
    this.redirect(location);
  }
};

/**
 * Retrieve user's OpenSocial profile from IBM Connections Cloud.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `ibm-connections-cloud`
 *   - `id`               the user's OpenSocial ID (urn:lsid:lconn.ibm.com:profiles.person:xxxx-xxx-x-x-x-x-x)
 *   - `userid`           the users id (id split after 'urn:lsid:lconn.ibm.com:profiles.person:')
 *   - `displayName`      the user's full name
 *   - `emails`           the proxied or contact email address granted by the user
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */

Strategy.prototype.userProfile = function userProfile(accessToken, done) {
  const self = this;

  this._oauth2.get(this._profileURL, accessToken, (err, body, response) => {
    if (err) {
      done(new InternalOAuthError('Failed to fetch user profile', err));
      return;
    }

    let json;
    try {
      json = JSON.parse(body);
    } catch (ex) {
      done(new Error('Failed to parse user profile'));
      return;
    }

    const profile = Profile.parse(json);
    profile.provider = self.name;
    profile._raw = body;
    profile._json = json;

    const setCookies = response && response.headers && response.headers['set-cookie'] ?
      response.headers['set-cookie'] :
      [];

    done(null, profile, setCookies);
  });
};

module.exports = Strategy;
