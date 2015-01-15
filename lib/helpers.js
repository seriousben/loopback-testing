var _describe = {};
var _it = {};
var _before = {};
var _after = {};
var helpers = exports = module.exports = {
  describe: _describe,
  it: _it,
  before: _before,
  after: _after
};
var assert = require('assert');
var request = require('supertest');
var expect = require('chai').expect;

_before.withApp = function(app) {
  if (app.models.User) {
    // Speed up the password hashing algorithm
    app.models.User.settings.saltWorkFactor = 4;
  }

  before(function() {
    this.app = app;
    var _request = this.request = request(app);
    this.post = _request.post;
    this.get = _request.get;
    this.put = _request.put;
    this.del = _request.del;
  });
}

_after.cleanDatasource = function(dsName) {
  after(function() {
    if (this.app) {
      this.app.datasources[dsName].automigrate();
      this.app.datasources[dsName].connector.ids = {};
    }
  });
}

function mixin(obj, into) {
  Object.keys(obj).forEach(function(key) {
    if (typeof obj[key] === 'function') {
      into[key] = obj[key];
    }
  });
}

_describe.staticMethod = function(methodName, cb) {
  describe('.' + methodName, function() {
    before(function() {
      this.method = methodName;
      this.isStaticMethod = true;
    });
    cb();
  });
}

_describe.instanceMethod = function(methodName, cb) {
  describe('.prototype.' + methodName, function() {
    before(function() {
      this.method = methodName;
      this.isInstanceMethod = true;
    });
    cb();
  });
}

_before.withArgs = function() {
  var args = Array.prototype.slice.call(arguments, 0);
  before(function() {
    this.args = args;
  });
}

_before.givenModel = function(modelName, attrs, optionalHandler) {
  var modelKey = modelName;

  if (typeof attrs === 'function') {
    optionalHandler = attrs;
    attrs = undefined;
  }

  if (typeof optionalHandler === 'string') {
    modelKey = optionalHandler;
  }

  attrs = attrs || {};

  before(function(done) {
    var test = this;
    var app = this.app;
    var model = app.models[modelName];
    assert(model, 'cannot get model of name ' + modelName +
      ' from app.models');
    assert(model.dataSource, 'cannot test model ' + modelName +
      ' without attached dataSource');
    assert(
      typeof model.create === 'function',
      modelName + ' does not have a create method'
    );

    model.create(attrs, function(err, result) {
      if (err) {
        console.error(err.message);
        if (err.details) console.error(err.details);
        done(err);
      } else {
        test[modelKey] = result;
        done();
      }
    });
  });

  if (typeof optionalHandler === 'function') {
    before(optionalHandler);
  }

  after(function(done) {
    this[modelKey].destroy(done);
  });
}

_before.givenUser = function(attrs, optionalHandler) {
  _before.givenModel('user', attrs, optionalHandler);
}

_before.givenUserWithRole = function(attrs, role, optionalHandler) {
  _before.givenUser(attrs, function(done) {
    var test = this;
    test.app.models.Role.create({
      name: role
    }, function(err, result) {
      if (err) {
        console.error(err.message);
        if (err.details) console.error(err.details);
        return done(err);
      }

      test.userRole = result;
      test.app.models.roleMapping.create({
          principalId: test.user.id,
          principalType: test.app.models.roleMapping.USER,
          roleId: result.id
        },
        function(err, result) {
          if (err) {
            console.error(err.message);
            if (err.details) console.error(err.details);
            return done(err);
          }

          test.userRoleMapping = result;
          done();
        }
      );
    });
  });

  if (typeof optionalHandler === 'function') {
    before(optionalHandler);
  }

  after(function(done) {
    var test = this;
    this.userRole.destroy(function(err) {
      if (err) return done(err);
      test.userRole = undefined;

      test.userRoleMapping.destroy(function(err) {
        if (err) return done(err);
        test.userRoleMapping = undefined;
        done();
      });
    });
  });
}

_before.givenLoggedInUser = function(credentials, optionalHandler) {
  _before.givenUser(credentials, function(done) {
    var test = this;
    this.user.constructor.login(credentials, function(err, token) {
      if (err) {
        done(err);
      } else {
        test.loggedInAccessToken = token;
        done();
      }
    });
  });

  after(function(done) {
    var test = this;
    this.loggedInAccessToken.destroy(function(err) {
      if (err) return done(err);
      test.loggedInAccessToken = undefined;
      done();
    });
  });
}

_before.givenLoggedInUserWithRole = function(credentials, role,
  optionalHandler) {
  _before.givenUserWithRole(credentials, role, function(done) {
    var test = this;
    this.user.constructor.login(credentials, function(err, token) {
      if (err) {
        done(err);
      } else {
        test.loggedInAccessToken = token;
        done();
      }
    });
  });

  after(function(done) {
    var test = this;
    this.loggedInAccessToken.destroy(function(err) {
      if (err) return done(err);
      test.loggedInAccessToken = undefined;
      done();
    });
  });
}

_before.givenAnUnauthenticatedToken = function(attrs, optionalHandler) {
  _before.givenModel('accessToken', attrs, optionalHandler);
}

_before.givenAnAnonymousToken = function(attrs, optionalHandler) {
  _before.givenModel('accessToken', {
    id: '$anonymous'
  }, optionalHandler);
}

_describe.whenCalledRemotely = function(verb, url, data, cb) {
  if (cb == undefined) {
    cb = data;
    data = null;
  }

  var urlStr = url;
  if (typeof url === 'function') {
    urlStr = '/<dynamic>';
  }

  describe(verb.toUpperCase() + ' ' + urlStr, function() {
    before(function(cb) {
      if (typeof url === 'function') {
        this.url = url.call(this);
      }
      this.remotely = true;
      this.verb = verb.toUpperCase();
      this.url = this.url || url;
      var methodForVerb = verb.toLowerCase();
      if (methodForVerb === 'delete') methodForVerb = 'del';

      if (this.request === undefined) {
        throw new Error(
          'App is not specified. Please use lt.before.withApp to specify the app.'
        );
      }

      this.http = this.request[methodForVerb](this.url);
      delete this.url;
      this.http.set('Accept', 'application/json');
      if (this.loggedInAccessToken) {
        this.http.set('authorization', this.loggedInAccessToken.id);
      }
      if (data) {
        var payload = data;
        if (typeof data === 'function')
          payload = data.call(this);
        this.http.send(payload);
      }
      this.req = this.http.req;
      var test = this;
      this.http.end(function(err) {
        test.req = test.http.req;
        test.res = test.http.res;
        delete test.url;
        cb();
      });
    });

    cb();
  });
}

_describe.whenLoggedInAsUser = function(credentials, cb) {
  describe('when logged in as user', function() {
    _before.givenLoggedInUser(credentials);
    cb();
  });
}

_describe.whenLoggedInAsUserWithRole = function(credentials, role, cb) {
  describe('when logged in as user', function() {
    _before.givenLoggedInUser(credentials, role);
    cb();
  });
}

_describe.whenCalledByUser = function(credentials, verb, url, data, cb) {
  describe('when called by logged in user', function() {
    _before.givenLoggedInUser(credentials);
    _describe.whenCalledRemotely(verb, url, data, cb);
  });
}

_describe.whenCalledByUserWithRole = function(credentials, role, verb, url,
  data, cb) {
  describe('when called by logged in user with role ' + role, function() {
    _before.givenLoggedInUserWithRole(credentials, role);
    _describe.whenCalledRemotely(verb, url, data, cb);
  });
}

_describe.whenCalledAnonymously = function(verb, url, data, cb) {
  describe('when called anonymously', function() {
    _before.givenAnAnonymousToken();
    _describe.whenCalledRemotely(verb, url, data, cb);
  });
}

_describe.whenCalledUnauthenticated = function(verb, url, data, cb) {
  describe('when called with unauthenticated token', function() {
    _before.givenAnAnonymousToken();
    _describe.whenCalledRemotely(verb, url, data, cb);
  });
}

_it.shouldBeAllowed = function() {
  it('should be allowed', function() {
    assert(this.req);
    assert(this.res);
    // expect success - status 2xx or 3xx
    expect(this.res.statusCode).to.be.within(100, 399);
  });
}

_it.shouldBeDenied = function() {
  it('should not be allowed', function() {
    assert(this.res);
    var expectedStatus = this.aclErrorStatus ||
      this.app && this.app.get('aclErrorStatus') ||
      401;
    expect(this.res.statusCode).to.equal(expectedStatus);
  });
}

_it.shouldNotBeFound = function() {
  it('should not be found', function() {
    assert(this.res);
    assert.equal(this.res.statusCode, 404);
  });
}

_it.shouldBeAllowedWhenCalledAnonymously =
  function(verb, url, data) {
    _describe.whenCalledAnonymously(verb, url, data, function() {
      _it.shouldBeAllowed();
    });
}

_it.shouldBeDeniedWhenCalledAnonymously =
  function(verb, url) {
    _describe.whenCalledAnonymously(verb, url, function() {
      _it.shouldBeDenied();
    });
}

_it.shouldBeAllowedWhenCalledUnauthenticated =
  function(verb, url, data) {
    _describe.whenCalledUnauthenticated(verb, url, data, function() {
      _it.shouldBeAllowed();
    });
}

_it.shouldBeDeniedWhenCalledUnauthenticated =
  function(verb, url) {
    _describe.whenCalledUnauthenticated(verb, url, function() {
      _it.shouldBeDenied();
    });
}

_it.shouldBeAllowedWhenCalledByUser =
  function(credentials, verb, url, data) {
    _describe.whenCalledByUser(credentials, verb, url, data, function() {
      _it.shouldBeAllowed();
    });
}

_it.shouldBeDeniedWhenCalledByUser =
  function(credentials, verb, url) {
    _describe.whenCalledByUser(credentials, verb, url, function() {
      _it.shouldBeDenied();
    });
}

_it.shouldBeAllowedWhenCalledByUserWithRole =
  function(credentials, role, verb, url, data) {
    _describe.whenCalledByUserWithRole(credentials, role, verb, url, data,
      function() {
        _it.shouldBeAllowed();
      });
}

_it.shouldBeDeniedWhenCalledByUserWithRole =
  function(credentials, role, verb, url) {
    _describe.whenCalledByUserWithRole(credentials, role, verb, url, function() {
      _it.shouldBeDenied();
    });
}
