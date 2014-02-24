var c14n = require("xml-c14n")(),
    connect = require("connect"),
    randomId = require("proquint-random-id"),
    saml2 = require("saml2"),
    url = require("url"),
    xmldom = require("xmldom"),
    xpath = require("xpath"),
    zlib = require("zlib");

var User = require("./lib/user");

var connect_saml2 = module.exports = function connect_saml2(options) {
  options = options || {};

  var urlencoded = connect.urlencoded(),
      canonicaliser = c14n.createCanonicaliser("http://www.w3.org/2001/10/xml-exc-c14n#");

  if (!options.idp) {
    throw Error("idp parameters are required");
  }

  if (!options.sp) {
    throw Error("sp parameters are required");
  }

  var idp = new saml2.IdentityProvider(options.idp),
      sp = new saml2.ServiceProvider(options.sp);

  var mountPrefix = options.mountPrefix || "",
      ssoConsumerPostPath = options.ssoConsumerPostPath || "/SAML2/AssertionConsumer/POST";

  var ensureAuthentication = !!options.ensureAuthentication,
      keepSignatures = !!options.keepSignatures;

  var saveAssertionXml = options.saveAssertionXml || function saveAssertionXml(assertionXml, req, cb) {
    req.session._saml = req.session._saml || {};
    req.session._saml.assertionXml = assertionXml;

    return cb();
  };

  var fetchAssertionXml = options.fetchAssertionXml || function fetchAssertionXml(req, cb) {
    return cb(null, (req.session && req.session._saml && req.session._saml.assertionXml) || null);
  };

  var removeAssertionXml = options.removeAssertionXml || function removeAssertionXml(req, cb) {
    if (req.session && req.session._saml && req.session._saml.assertionXml) {
      delete req.session._saml.assertionXml;
    }

    return cb();
  };

  var saveRelayState = options.saveRelayState || function saveRelayState(req, id, relayState, cb) {
    req.session._saml = req.session._saml || {};
    req.session._saml.relayState = req.session._saml.relayState || {};
    req.session._saml.relayState[id] = relayState;

    return cb();
  };

  var fetchRelayState = options.fetchRelayState || function fetchRelayState(req, id, cb) {
    var relayState = null;

    if (req.session && req.session._saml && req.session._saml.relayState && req.session._saml.relayState[id]) {
      relayState = req.session._saml.relayState[id];

      delete req.session._saml.relayState[id];
    }

    return cb(null, relayState);
  };

  return function connect_saml2(req, res, next) {
    req.removeAssertion = function removeAssertion(done) {
      req.samlAssertion = null;

      return removeAssertionXml(req, done);
    };

    req.initiateAuthentication = function initiateAuthentication() {
      var authnRequest = sp.createAuthnRequest();

      return canonicaliser.canonicalise(authnRequest.toDocument(), function(err, authnRequestXml) {
        if (err) {
          return next(err);
        }

        return zlib.deflateRaw(authnRequestXml, function(err, authnRequestDeflatedXml) {
          if (err) {
            return next(err);
          }

          var relayState = {
            initiationTime: new Date().toISOString(),
            previousUrl: req.url,
          };

          var relayStateId = Date.now() + "-" + randomId();

          var parameters = {
            SAMLEncoding: "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE",
            SAMLRequest: authnRequestDeflatedXml.toString("base64"),
            RelayState: relayStateId,
          };

          var uri = url.parse(idp.singleSignOnService, true);

          for (var k in parameters) {
            uri.query[k] = parameters[k];
          }

          return saveRelayState(req, relayStateId, relayState, function(err) {
            if (err) {
              return next(err);
            }

            res.writeHead(302, {
              location: url.format(uri),
            });

            return res.end();
          });
        });
      });
    };

    fetchAssertionXml(req, function(err, storedAssertionXml) {
      if (err) {
        return next(err);
      }

      if (storedAssertionXml) {
        try {
          var storedAssertionDocument = (new xmldom.DOMParser()).parseFromString(storedAssertionXml);
          var storedAssertion = saml2.Protocol.fromDocument(storedAssertionDocument);
        } catch (e) {
          return next(e);
        }

        var authnStatementElement = xpath.select1("./*[namespace-uri()='urn:oasis:names:tc:SAML:2.0:assertion' and local-name()='Assertion']/*[namespace-uri()='urn:oasis:names:tc:SAML:2.0:assertion' and local-name()='AuthnStatement']", storedAssertionDocument);
        var sessionNotOnOrAfter = null;
        if (authnStatementElement) {
          sessionNotOnOrAfter = authnStatementElement.getAttribute("SessionNotOnOrAfter");
        }

        req.samlAssertionDocument = storedAssertionDocument;
        req.samlAssertion = storedAssertion;
        req.user = new User({
          expiresAt: sessionNotOnOrAfter ? new Date(sessionNotOnOrAfter) : null,
          id: xpath.select1("./*[namespace-uri()='urn:oasis:names:tc:SAML:2.0:assertion' and local-name()='Assertion']/*[namespace-uri()='urn:oasis:names:tc:SAML:2.0:assertion' and local-name()='Subject']/*[namespace-uri()='urn:oasis:names:tc:SAML:2.0:assertion' and local-name()='NameID']/text()", storedAssertionDocument) + "",
          attributes: xpath.select("./*[namespace-uri()='urn:oasis:names:tc:SAML:2.0:assertion' and local-name()='Assertion']/*[namespace-uri()='urn:oasis:names:tc:SAML:2.0:assertion' and local-name()='AttributeStatement']/*[namespace-uri()='urn:oasis:names:tc:SAML:2.0:assertion' and local-name()='Attribute']", storedAssertionDocument).map(function(attributeElement) {
            var attribute = saml2.Protocol.fromDocument(attributeElement);

            return [
              attribute.value.name,
              attribute.value.attributeValue.map(function(e) {
                return e.value;
              }),
            ];
          }).reduce(function(i, v) {
            i[v[0]] = i[v[0]] || [];
            i[v[0]] = i[v[0]].concat(v[1]);
            return i;
          }, {}),
        });

        if (sessionNotOnOrAfter && new Date(sessionNotOnOrAfter).valueOf() <= Date.now()) {
          delete req.samlAssertion;
          delete req.user;
        }
      }

      if (req.url === ssoConsumerPostPath && req.method === "POST") {
        return urlencoded(req, res, function onParsedBody(err) {
          if (err) {
            return next(err);
          }

          if (!req.body.SAMLResponse) {
            return next(Error("couldn't find SAML response field"));
          }

          var samlResponseXml = Buffer(req.body.SAMLResponse, "base64").toString();

          var parser = new xmldom.DOMParser();

          try {
            var samlResponseDocument = parser.parseFromString(samlResponseXml);
          } catch (e) {
            return next(e);
          }

          if (samlResponseDocument.documentElement.namespaceURI !== "urn:oasis:names:tc:SAML:2.0:protocol" && samlResponseDocument.documentElement.localName !== "Response") {
            return next(Error("expected a {urn:oasis:names:tc:SAML:2.0:protocol}Response but got a {" + samlResponseDocument.documentElement.namespaceURI + "}" + samlResponseDocument.documentElement.localName));
          }

          return idp.verify(samlResponseDocument, function onVerification(err, signatureInfo) {
            if (err) {
              return next(err);
            }

            var statusElement = xpath.select1("./*[namespace-uri()='urn:oasis:names:tc:SAML:2.0:protocol' and local-name()='Response']/*[namespace-uri()='urn:oasis:names:tc:SAML:2.0:protocol' and local-name()='Status']/*[namespace-uri()='urn:oasis:names:tc:SAML:2.0:protocol' and local-name()='StatusCode']", samlResponseDocument);

            if (!statusElement) {
              return next(Error("couldn't find status element in saml response"));
            }

            try {
              var status = saml2.Protocol.fromDocument(statusElement);
            } catch (e) {
              return next(e);
            }

            if (status.value !== "urn:oasis:names:tc:SAML:2.0:status:Success") {
              return next("saml response did not indicate a success status");
            }

            var assertionElement = xpath.select1("./*[namespace-uri()='urn:oasis:names:tc:SAML:2.0:protocol' and local-name()='Response']/*[namespace-uri()='urn:oasis:names:tc:SAML:2.0:assertion' and local-name()='Assertion']", samlResponseDocument);

            if (!assertionElement) {
              return next(Error("couldn't find assertion in saml response"));
            }

            var conditions = xpath.select1("./*[namespace-uri()='urn:oasis:names:tc:SAML:2.0:assertion' and local-name()='Conditions']", assertionElement);
            if (conditions) {
              // we don't use the protocol stuff here because it kills our dates

              var notBefore = conditions.getAttribute("NotBefore"),
                  notOnOrAfter = conditions.getAttribute("NotOnOrAfter");

              if (notBefore && new Date(notBefore).valueOf() > Date.now()) {
                return next(Error("NotBefore condition not satisfied"));
              }

              if (notOnOrAfter && new Date(notOnOrAfter).valueOf() <= Date.now()) {
                return next(Error("NotOnOrAfter condition not satisfied"));
              }
            }

            if (!keepSignatures) {
              // remove signatures from saved assertion unless specified not to
              var signatures = xpath.select("//*[namespace-uri()='http://www.w3.org/2000/09/xmldsig#' and local-name()='Signature']", assertionElement);

              for (var i=0;i<signatures.length;++i) {
                if (signatures[i].parentNode) {
                  signatures[i].parentNode.removeChild(signatures[i]);
                }
              }
            }

            return canonicaliser.canonicalise(assertionElement, function(err, assertionXml) {
              if (err) {
                return next(err);
              }

              return saveAssertionXml(assertionXml, req, function(err) {
                if (err) {
                  return next(err);
                }

                if (!req.body.RelayState) {
                  res.writeHead(302, {
                    location: "/",
                  });

                  return res.end();
                }

                return fetchRelayState(req, req.body.RelayState, function(err, relayState) {
                  if (err) {
                    return next(err);
                  }

                  if (typeof relayState !== "object" || relayState === null || !relayState.previousUrl) {
                    res.writeHead(302, {
                      location: "/",
                    });

                    return res.end();
                  }

                  res.writeHead(302, {
                    location: relayState.previousUrl,
                  });

                  return res.end();
                });
              });
            });
          });
        });
      }

      if (ensureAuthentication && !req.user) {
        return req.initiateAuthentication();
      }

      return next();
    });
  };
};
