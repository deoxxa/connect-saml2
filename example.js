#!/usr/bin/env node

var connect = require("connect"),
    connect_saml2 = require("./"),
    http = require("http");

var app = connect();

app.use(connect.logger());

// connect's cookieParser and session are required for the *default* relayState
// and assertion storage strategies. They are *not* required if these mechanisms
// are overridden.

app.use(connect.cookieParser());
app.use(connect.session({secret: "secret"}));

app.use(connect_saml2({
  ensureAuthentication: true,
  idp: {
    singleSignOnService: "https://openidp.feide.no/simplesaml/saml2/idp/SSOService.php",
    fingerprint: "C9:ED:4D:FB:07:CA:F1:3F:C2:1E:0F:EC:15:72:04:7E:B8:A7:A4:CB",
  },
  sp: {
    entityId: "fknsrsbiz-testing",
  },
}));

app.use(function(req, res, next) {
  return res.end(JSON.stringify(req.user));
});

var server = http.createServer(app);

server.listen(3000, function() {
  console.log("listening");
});
