var assert, authorization;

assert = require("assert");

authorization = require("../");

describe("ensureRequest", function() {
  var checkDenied,
    checkMiddleware,
    checkPermitted,
    checkRedirectedElsewhere,
    httpContextMock;
  httpContextMock = function(result, done) {
    var self;
    self = this;
    this.done = done;
    this.result = result;
    result.redirectedTo = void 0;
    result.nextCalled = false;
    this.req = {
      session: {
        user: {
          permissions: [
            "identity:view",
            "session:*",
            "system:list,view,edit",
            "version:v2??"
          ]
        }
      }
    };
    this.res = {
      redirect: function(url) {
        self.result.redirectedTo = url;
        if (self.done) {
          return self.done();
        }
      }
    };
    return (this.next = function() {
      self.result.nextCalled = true;
      if (self.done) {
        return self.done();
      }
    });
  };
  checkMiddleware = function(middleware, result, done, check) {
    var httpContext;
    httpContext = new httpContextMock(result, function() {
      var e;
      try {
        check(result);
        return done();
      } catch (_error) {
        e = _error;
        return done(e);
      }
    });
    return middleware(httpContext.req, httpContext.res, httpContext.next);
  };
  checkPermitted = function(result) {
    assert.equal(result.redirectedTo, void 0);
    return assert.equal(result.nextCalled, true);
  };
  checkDenied = function(result) {
    assert.equal(result.redirectedTo, "/login");
    return assert.equal(result.nextCalled, false);
  };
  checkRedirectedElsewhere = function(result) {
    assert.equal(result.redirectedTo, "/elsewhere");
    return assert.equal(result.nextCalled, false);
  };
  it("permitted", function(done) {
    var middleware, result;
    result = {};
    middleware = authorization.isPermitted("identity:view");
    return checkMiddleware(middleware, result, done, checkPermitted);
  });
  it("permitted asserting multiple permissions", function(done) {
    var middleware, result;
    result = {};
    middleware = authorization.isPermitted("identity:view", "system:list");
    return checkMiddleware(middleware, result, done, checkPermitted);
  });
  it("denied", function(done) {
    var middleware, result;
    result = {};
    middleware = authorization.isPermitted("identity:edit");
    return checkMiddleware(middleware, result, done, checkDenied);
  });
  it("denied asserting multiple permissions", function(done) {
    var middleware, result;
    result = {};
    middleware = authorization.isPermitted(["identity:view", "system:reboot"]);
    return checkMiddleware(middleware, result, done, checkDenied);
  });
  it("denied redirectTo", function(done) {
    var middleware, result;
    result = {};
    middleware = authorization
      .redirectTo("/elsewhere")
      .isPermitted("identity:edit");
    return checkMiddleware(middleware, result, done, checkRedirectedElsewhere);
  });
  it("or custom permission check - permitted", function(done) {
    var middleware, result;
    result = {};
    middleware = authorization.isPermitted(function(claim) {
      return (
        claim.isPermitted("identity:edit") || claim.isPermitted("identity:view")
      );
    });
    return checkMiddleware(middleware, result, done, checkPermitted);
  });
  it("and custom permission check - denied", function(done) {
    var middleware, result;
    result = {};
    middleware = authorization.isPermitted(function(claim) {
      return (
        claim.isPermitted("identity:edit") && claim.isPermitted("identity:view")
      );
    });
    return checkMiddleware(middleware, result, done, checkDenied);
  });
  it("denied handler", function(done) {
    var middleware, result;
    result = {};
    middleware = authorization
      .onDenied(function(req, res, next) {
        result.onDeniedCalled = true;
        return res.redirect("/elsewhere");
      })
      .isPermitted("identity:edit");
    return checkMiddleware(middleware, result, done, function() {
      assert.equal(result.onDeniedCalled, true);
      return checkRedirectedElsewhere(result);
    });
  });
  it("custom considerPermissions", function(done) {
    var middleware, result;
    result = {};
    middleware = authorization
      .withPermissions(function(req, res) {
        result.withPermissionsCalled = true;
        return ["identity:*"];
      })
      .isPermitted("identity:edit");
    return checkMiddleware(middleware, result, done, function() {
      assert.equal(result.withPermissionsCalled, true);
      return checkPermitted(result);
    });
  });
  it("custom asynchronous considerPermissions", function(done) {
    var middleware, result;
    result = {};
    middleware = authorization
      .withPermissions(function(req, res, done) {
        result.withPermissionsCalled = true;
        return done(["identity:*"]);
      })
      .isPermitted("identity:edit");
    return checkMiddleware(middleware, result, done, function() {
      assert.equal(result.withPermissionsCalled, true);
      return checkPermitted(result);
    });
  });
  it("custom considerSubject", function(done) {
    var middleware, result;
    result = {};
    middleware = authorization
      .withSubject(function(req, res) {
        var user;
        result.withPermissionsCalled = true;
        user = {
          username: "administrator",
          permissions: "*:*"
        };
        return user;
      })
      .isPermitted("identity:edit");
    return checkMiddleware(middleware, result, done, function() {
      assert.equal(result.withPermissionsCalled, true);
      return checkPermitted(result);
    });
  });
  it("custom asynchronous considerSubject", function(done) {
    var middleware, result;
    result = {};
    middleware = authorization
      .withSubject(function(req, res, done) {
        var user;
        result.withPermissionsCalled = true;
        user = {
          username: "administrator",
          permissions: "*:*"
        };
        return done(user);
      })
      .isPermitted("identity:edit");
    return checkMiddleware(middleware, result, done, function() {
      assert.equal(result.withPermissionsCalled, true);
      return checkPermitted(result);
    });
  });
  it("permitted new EnsureRequest", function(done) {
    var ensureRequest, middleware, result;
    result = {};
    ensureRequest = new authorization();
    middleware = ensureRequest.isPermitted("identity:view");
    return checkMiddleware(middleware, result, done, checkPermitted);
  });
  return it("custom options", function(done) {
    var ensureRequest, middleware, result;
    result = {};
    ensureRequest = new authorization();
    ensureRequest.options.redirectTo = "/elsewhere";
    middleware = ensureRequest.isPermitted("identity:edit");
    return checkMiddleware(middleware, result, done, checkRedirectedElsewhere);
  });
});

// ---
// generated by coffee-script 1.9.2
