var User = module.exports = function User(options) {
  this.expiresAt = options.expiresAt || null;
  this.attributes = options.attributes || {};
};

User.prototype.getAttributes = function getAttributes(name) {
  return this.attributes[name];
};

User.prototype.getAttribute = function getAttribute(name) {
  return (this.attributes[name] || [null])[0];
};
