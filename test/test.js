// node core modules

// 3rd party modules
import test from 'ava';

// internal modules
import { Strategy } from '../lib/index';

test('calling constructor with bare minimum', (t) => {
  const myTest = () =>
    new Strategy(
      {
        hostname: 'my.hostname.com',
        callbackURL: 'https://my.host.com/callback',
        clientID: '1234',
        clientSecret: 'sssshhhh',
      },
      () => {}
    );
  t.notThrows(myTest);
});
