/**
 * Reconstructs the original URL of the request.
 *
 * This function builds a URL that corresponds the original URL requested by the
 * client, including the protocol (http or https) and host.
 *
 * If the request passed through any proxies that terminate SSL, the
 * `X-Forwarded-Proto` header is used to detect if the request was encrypted to
 * the proxy, assuming that the proxy has been flagged as trusted.
 *
 * @param {http.IncomingMessage} req
 * @param {Object} [options]
 * @return {String}
 * @api private
 */

function originalURL(req, params = {}) {
  const { app } = req;

  const options = Object.assign({}, params);
  if (app && app.get && app.get('trust proxy')) {
    options.proxy = true;
  }
  const trustProxy = options.proxy;

  const proto = (req.headers['x-forwarded-proto'] || '').toLowerCase();
  const tls = req.connection.encrypted || (trustProxy && proto.split(/\s*,\s*/)[0] === 'https');
  const host = (trustProxy && req.headers['x-forwarded-host']) || req.headers.host;
  const protocol = tls ? 'https' : 'http';
  const path = req.url || '';

  return `${protocol}://${host}${path}`;
}

module.exports = { originalURL };
