'use strict';

import test from 'ava';
import gravity from '../lib/index';

test('awesome:test', (t) => {
  const message = 'everything is awesome';
  t.is(gravity('awesome'), message, message);
});
