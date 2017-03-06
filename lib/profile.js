/**
 * Parse profile.
 *
 * @param {Object|String} json
 * @return {Object}
 * @api private
 */

function parse(data) {
  const json = ((val) => {
    if (typeof val === 'string') {
      return JSON.parse(val);
    }
    return val;
  })(data);

  const profile = {};
  profile.id = json.entry.id;
  profile.displayName = json.entry.displayName;
  profile.userid = profile.id.split('urn:lsid:lconn.ibm.com:profiles.person:')[1];

  if (json.entry.emails) {
    profile.emails = json.entry.emails;
  }

  return profile;
}

module.exports = { parse };
