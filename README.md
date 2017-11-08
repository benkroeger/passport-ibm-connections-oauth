[![NPM info](https://nodei.co/npm/passport-ibm-connections-oauth.png?downloads=true)](https://nodei.co/npm/passport-ibm-connections-oauth.png?downloads=true)

[![dependencies](https://david-dm.org/benkroeger/passport-ibm-connections-oauth.png)](https://david-dm.org/benkroeger/passport-ibm-connections-oauth.png)

> Passport oAuth 2.0 Strategy for IBM Connections on-prem

## Install

```sh
$ npm install --save passport-ibm-connections-oauth
```


## Usage

```javascript
'use strict';

const express = require('express');
const passport = require('passport');
const { Strategy } = require('passport-ibm-connections-oauth');

const app = express();

const strategyParams = {
  hostname: 'apps.na.collabserv.com',
  clientID: 'your client id',
  clientSecret: 'your client secret',
  callbackURL: 'https://your-host.com/auth/ibm-connections-oauth/callback',
  // optionally define your own `authorizationURL` and `tokenURL` (e.g. when using with IBM Connections >= 5.5)
  authorizationURL: '/oauth2/endpoint/connectionsProvider/authorize',
  tokenURL: '/oauth2/endpoint/connectionsProvider/token',
};

// setup passport to use this strategy
passport.use(new Strategy(strategyParams, (accessToken, refreshToken, params, profile, done) => {
  // do your magic to load or create a local user here
  done();
}));

const router = express.Router();
router
  .get(
    '/',
    passport.authenticate('ibm-connections-oauth', {
      session: false,
    })
  )
  .get(
    '/callback',
    passport.authenticate('ibm-connections-oauth', {
      failureRedirect: '/account/login',
      session: false,
    }),
    (req, res, next) => {
      // e.g. create a jwt for your application and return to client
      next();
    }
  );

app.use('/auth/ibm-connections-oauth', router);


```

## License

MIT © [Benjamin Kroeger]()
