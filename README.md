connect-saml2
=============

SAML2 authentication for connect

Overview
--------

This connect middleware allows an application to authenticate users via a SAML2
gateway, and access the attributes asserted by the gateway pertaining to those
users. It doesn't require (and probably doesn't play nicely with) any other
authentication framework. Currently connect ~2.0.0 is supported. As long as the
`urlencoded` middleware doesn't go away, things should keep working for quite
some time.

Usage
-----

```js
var connect = require("connect"),
    connect_saml2 = require("connect-saml2");

var app = connect();

// required only for the default user/session logic - see below for details
app.use(connect.cookieParser());
app.use(connect.session({secret: "i am a secret lol"}));

app.use(connect_saml2({
  // force users to authenticate before they can pass through this middleware
  ensureAuthentication: true,
  // this is information about your SAML gateway
  idp: {
    singleSignOnService: "http://www.example.com/sso",
    fingerprint: "01:23:45:...",
  },
  // this is information about your application
  sp: {
    entityId: "my-application",
  },
}));

// anyone getting to this point will have authenticated already, so you can rely
// on req.user existing, because we specified `ensureAuthentication: true` above
app.use(function(req, res) {
  res.writeHead(200, {
    "content-type": "application/json",
  });

  return res.end(JSON.stringify(req.user, null, 2));
});
```

Logic
-----

This middleware is designed to sit right up near the top of your middleware
stack, after your header parsing and session stuff but before your body parsing.
This is so that it can parse urlencoded requests, and so that it can stop users
from hitting your main application logic (if you choose to have it do so.)

Upon a request entering the middleware, `connect_saml2` will check to see if
there's a currently-valid SAML context that it knows about. It will, by default,
do this by looking in the user's session. If there is a valid context, a few
properties of `req` will be populated: `samlAssertion`, `samlAssertionXml`, and
`user`. The request will then be passed along and allowed to continue.

If there is no current SAML context, and the `ensureAuthentication` option has
been specified and is `true`, the user will be shuttled into the authentication
process, involving a redirect to the SAML gateway, and from there back to our
assertion consumer (which is part of this middleware.)

`req` Augmentations
-------------------

The properties mentioned above are as follows:

* **samlAssertion** - a parsed and (somewhat) validated version of the original
  assertion sent by the SAML gateway.
* **samlAssertionXml** - this is a DOM object representing the assertion, with
  namespaces and such intact.
* **user** - this is a `User` object based on the assertion received

There is also an `initiateAuthentication` method that can be used to initiate
the authentication process. It'd usually be used something like so:

```js
app.use(function(req, res, next) {
  if (!req.user) {
    return req.initiateAuthentication();
  }

  res.end("hello, " + req.user.getAttribute("firstName"));
});
```

`User` Object
-------------

This object holds some information about a SAML context.

### User Properties

* **expiresAt** - the time that the context expires
* **attributes** - a map of attribute names to attribute value collections

### User Methods

* **getAttributes(name)** - gets the collection of attributes under the name
  `name`
* **getAttribute(name)** - as above, but only gets the first value in the
  collection (or `null`)

Parameters
----------

### idp

* Type: `object`
* Required: yes

This is an object that gets used as the instantiation options for the
IdentityProvider object from the `saml2` library. This includes things like the
SSO service URL, the certificate or fingerprint, etc.

### sp

* Type: `object`
* Required: yes

This is like the `idp` parameter -- it's passed as-is into the constructor for a
`ServiceProvider` object from the `saml2` library. This contains the entity ID
for the service and optionally the private key and certificate used to sign
messages.

### ensureAuthentication

* Type: `boolean`
* Required: no
* Default: `false`

Tells `connect_saml2` whether or not to force all users through the
authentication process before passing through to the next handler.

### mountPrefix

* Type: `string`
* Required: no
* Default: `""`

Useful in express applications where the middleware is located somewhere other
than "/". In this case, set it to the mount point of the middleware (for example
`/auth/saml`.)

### ssoConsumerPostPath

* Type: `string`
* Required: no
* Default: `"/SAML2/AssertionConsumer/POST"`

This controls what URL the middleware will pay attention to for consuming SAML
assertions sent via the HTTP POST binding.

### saveAssertionXml

* Type: `function(assertionXml, req, cb)`
* Required: no
* Default: (see below)

```js
// default function
function saveAssertionXml(assertionXml, req, cb) {
  req.session._saml = req.session._saml || {};
  req.session._saml.assertionXml = assertionXml;

  return cb();
};
```

### fetchAssertionXml

* Type: `function(req, cb)`
* Required: no
* Default: (see below)

```js
// default function
function fetchAssertionXml(req, cb) {
  return cb(null, (req.session && req.session._saml && req.session._saml.assertionXml) || null);
};
```

### removeAssertionXml

* Type: `function(req, cb)`
* Required: no
* Default: (see below)

```js
// default function
function removeAssertionXml(req, cb) {
  if (req.session && req.session._saml && req.session._saml.assertionXml) {
    delete req.session._saml.assertionXml;
  }

  return cb();
};
```

### saveRelayState

* Type: `function(req, id, relayState, cb)`
* Required: no
* Default: (see below)

```js
// default function
function saveRelayState(req, id, relayState, cb) {
  req.session._saml = req.session._saml || {};
  req.session._saml.relayState = req.session._saml.relayState || {};
  req.session._saml.relayState[id] = relayState;

  return cb();
};
```

### fetchRelayState

* Type: `function(req, id, cb)`
* Required: no
* Default: (see below)

```js
// default function
function fetchRelayState(req, id, cb) {
  var relayState = null;

  if (req.session && req.session._saml && req.session._saml.relayState && req.session._saml.relayState[id]) {
    relayState = req.session._saml.relayState[id];

    delete req.session._saml.relayState[id];
  }

  return cb(null, relayState);
};
```

License
-------

3-clause BSD. A copy is included with the source.

Contact
-------

* GitHub ([deoxxa](http://github.com/deoxxa))
* Twitter ([@deoxxa](http://twitter.com/deoxxa))
* Email ([deoxxa@fknsrs.biz](mailto:deoxxa@fknsrs.biz))
