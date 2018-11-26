var ACL, _, acls_obj, safeEval;
(bind = function(fn, me) {
  return function() {
    return fn.apply(me, arguments);
  };
}),
  (indexOf =
    [].indexOf ||
    function(item) {
      for (var i = 0, l = this.length; i < l; i++) {
        if (i in this && this[i] === item) return i;
      }
      return -1;
    });

_ = require("underscore");
safeEval = require("safe-eval");

acls_obj = {
  is_admin: "subject.is_admin == false",
  is_owner: "subject._id == resource._id",
  is_user: "subject._id != resource._id",
  user_deny: "subject._id != resource._id",
  is_auth: "subject._id != resource._id"
};

ACL = (function() {
  function ACL(options) {
    this._getFromAdapter = bind(this._getFromAdapter, this);
    this._objectValidate = bind(this._objectValidate, this);
    this._arrayValidate = bind(this._arrayValidate, this);
    this._stringValidate = bind(this._stringValidate, this);
    this._defaultValidate = bind(this._defaultValidate, this);
    this._validate = bind(this._validate, this);
    this.validate = bind(this.validate, this);
    this.initiliaze = bind(this.initiliaze, this);
    this.initiliaze(options);
  }

  ACL.prototype.initiliaze = function(options) {
    this.subject = options.subject;
    this.resource = options.resource;
    this.options = options.options;
    return (this.defaultPolicy = options.defaultPolicy | false);
  };

  ACL.prototype.operators = {
    $and: {
      startValue: true,
      operator: "and"
    },
    $or: {
      startValue: false,
      operator: "or"
    },
    $not: {
      startValue: null,
      operator: "not"
    }
  };

  ACL.prototype.validate = function(ensure, acls, callback) {
    var acl,
      acl_validation,
      allow_acl,
      allow_acls,
      deny_acl,
      deny_acls,
      i,
      len,
      policy,
      res,
      result,
      x,
      y;
    this.ensure = ensure;
    allow_acls = [];
    deny_acls = [];
    acl_validation = [];
    for (i = 0, len = acls.length; i < len; i++) {
      acl = acls[i];
      if (acl.allow == null) {
        allow_acl = this.defaultPolicy;
      }
      if (acl.deny == null) {
        deny_acl = this.defaultPolicy;
      }
      if (acl.allow != null) {
        allow_acl = this._validate(acl.allow);
      }
      if (acl.deny != null) {
        deny_acl = this._validate(acl.deny);
      }
      x = deny_acl;
      y = allow_acl;
      policy = !x && y;
      res = {
        access: acl.access,
        result: policy
      };
      acl_validation.push(res);
      if (policy) {
        result = res;
        break;
      }
    }
    if (!result) {
      result = {
        access: null,
        result: false
      };
    }
    return callback(result);
  };

  ACL.prototype._validate = function(rules) {
    var result, validate;
    validate =
      rules instanceof Array
        ? "_arrayValidate"
        : "_" + typeof rules + "Validate";
    if (this[validate] != null) {
      result = this[validate](rules);
    } else {
      result = this._defaultValidate(rules);
    }
    return result;
  };

  ACL.prototype._defaultValidate = function(acls) {
    return this.defaultPolicy;
  };

  ACL.prototype._stringValidate = function(acl) {
    var current_acl, options, resource, result, subject, context;
    current_acl = this._getFromAdapter(acl);
    if (current_acl == null) {
      return this.defaultPolicy;
    }
    subject = this.subject;
    resource = this.resource;
    options = this.options;
    context = Object.assign(
      {},
      {
        subject,
        resource
      }
    );
    try {
      result = safeEval(current_acl, context);
    } catch (e) {
      console.log(e);
      return false;
    }
    return result;
  };

  ACL.prototype._arrayValidate = function(acls, operator) {
    var result;
    if (operator == null) {
      operator = "$and";
    }
    result = _.reduce(
      acls,
      (function(_this) {
        return function(start, acl) {
          var acl_result;
          acl_result = _this._stringValidate(acl);
          switch (_this.operators[operator].operator) {
            case "and":
              return start && acl_result;
            case "or":
              return start || acl_result;
            default:
              return acl_result;
          }
        };
      })(this),
      this.operators[operator].startValue
    );
    return result;
  };

  ACL.prototype._objectValidate = function(acls) {
    var key, operator, results, rules, validate, value;
    results = [];
    for (key in acls) {
      value = acls[key];
      operator = key;
      rules = value;
      validate =
        rules instanceof Array
          ? "_arrayValidate"
          : "_" + typeof rules + "Validate";
      if (
        this[validate] != null &&
        indexOf.call(Object.keys(this.operators), operator) >= 0
      ) {
        results.push(this[validate](rules, operator));
      } else {
        results.push(this._defaultValidate(rules));
      }
    }
    return _.reduce(
      results,
      (function(_this) {
        return function(start, result) {
          return result && start;
        };
      })(this),
      true
    );
  };

  ACL.prototype._getFromAdapter = function(acl) {
    var adapter, name, ref;
    ref = this.ensure._adapters;
    for (name in ref) {
      adapter = ref[name];
      acl = adapter.findACL(acl);
      if (acl != null) {
        return acl;
      }
    }
  };

  return ACL;
})();

module.exports = ACL;

// ---
// generated by coffee-script 1.9.2
