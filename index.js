'use strict';

module.exports.create = function (options) {



  var crypto = require('crypto');
  var defaults = {};
  var memDb = {
    accountKeypairs: {}
  , certificateKeypairs: {}
  , accountIndices: {}
  , certIndices: {}
  , certificates: {}
  , accounts: {}
  , accountCerts: {}
  };



  var accounts = {
    // Accounts
    setKeypair: function (opts, keypair, cb) {
      // opts.email // non-optional
      // opts.keypair // non-optional

      if (!opts.email) {
        cb(new Error("MUST use email when setting Keypair"));
        return;
      }

      if (!keypair.privateKeyJwk) {
        cb(new Error("MUST use privateKeyJwk when setting Keypair"));
        return;
      }
      if (!keypair.privateKeyPem) {
        cb(new Error("MUST use privateKeyPem when setting Keypair"));
        return;
      }
      if (!keypair.publicKeyPem) {
        cb(new Error("MUST use publicKeyPem when setting Keypair"));
        return;
      }

      var accountId = crypto.createHash('sha256').update(keypair.publicKeyPem).digest('hex');

      memDb.accountIndices[accountId] = accountId;
      memDb.accountIndices[opts.email] = accountId;
      memDb.accountKeypairs[accountId] = keypair;
      /*
      {
        id: accountId
        // TODO nix accountId
      , accountId: accountId
      , email: opts.email
      , keypair: keypair
      };
      */

      cb(null, memDb.accounts[accountId]);
    }
    // Accounts
  , checkKeypair: function (opts, cb) {
      // opts.email // optional
      // opts.accountId // optional

      var keypair = opts.keypair || {};
      var index;

      if (keypair.publicKeyPem) {
        index = crypto.createHash('sha256').update(keypair.publicKeyPem).digest('hex');
        index = memDb.accountIndices[index];
      }
      else if (keypair.publicKeyJwk) {
        // TODO RSA.exportPublicPem(keypair);
        cb(new Error("id from publicKeyJwk not yet implemented"));
        return;
      }
      else if (opts.email) {
        index = memDb.accountIndices[opts.email];
      }
      else {
        cb(new Error("MUST supply email or keypair.publicKeyPem or keypair.publicKeyJwk"));
        return;
      }

      cb(null, memDb.accountKeypairs[index] || null);
    }



    // Accounts
  , set: function (opts, reg, cb) {
      // opts.email
      // reg.keypair
      // reg.receipt // response from acme server

      var keypair = reg.keypair || opts.keypair || {};
      var accountId;
      var index;

      if (keypair.publicKeyPem) {
        index = crypto.createHash('sha256').update(keypair.publicKeyPem).digest('hex');
        index = memDb.accountIndices[index];
      }
      else if (keypair.publicKeyJwk) {
        // TODO RSA.exportPublicPem(keypair);
        cb(new Error("id from publicKeyJwk not yet implemented"));
        return;
      }
      else if (opts.email) {
        index = memDb.accountIndices[opts.email];
      }
      else {
        cb(new Error("MUST supply email or keypair.publicKeyPem or keypair.publicKeyJwk"));
        return;
      }

      accountId = memDb.accountIndices[index];
      if (!accountId) {
        cb(new Error("keypair was not previously set with email and keypair.publicKeyPem"));
        return;
      }

      memDb.accounts[accountId] = {
        id: accountId
        // TODO nix accountId
      , accountId: accountId
      , email: opts.email
      , keypair: keypair
      , agreeTos: opts.agreeTos || reg.agreeTos
      //, receipt: reg.receipt || opts.receipt
      };
      Object.keys(reg).forEach(function (key) {
        memDb.accounts[accountId][key] = reg[key];
      });



      cb(null, memDb.accounts[accountId]);
    }
    // Accounts
  , check: function (opts, cb) {
      // opts.email // optional
      // opts.accountId // optional
      // opts.domains // optional

      var keypair = opts.keypair || {};
      var index;
      var accountId;
      var account;

      if (opts.accountId) {
        index = memDb.accountIndices[opts.accountId];
      }
      else if (keypair.publicKeyPem) {
        index = crypto.createHash('sha256').update(keypair.publicKeyPem).digest('hex');
        index = memDb.accountIndices[index];
      }
      else if (keypair.publicKeyJwk) {
        // TODO RSA.exportPublicPem(keypair);
        cb(new Error("id from publicKeyJwk not yet implemented"));
        return;
      }
      else if (opts.email) {
        index = memDb.accountIndices[opts.email];
      }
      else if (opts.domains && opts.domains[0]) {
        index = memDb.accountIndices[opts.domains[0]];
      }
      else {
        console.error(opts);
        cb(new Error("MUST supply email or keypair.publicKeyPem or keypair.publicKeyJwk"));
        return;
      }

      accountId = memDb.accountIndices[index];
      if (!accountId) {
        cb(null, null);
        return;
      }

      account = JSON.parse(JSON.stringify(memDb.accounts[accountId] || null));
      account.keypair = memDb.accountKeypairs[accountId] || null;

      cb(null, account);
    }
  };



  var certificates = {
    // Certificates
    setKeypair: function (opts, keypair, cb) {
      // opts.domains

      if (!opts.domains || !opts.domains.length) {
        cb(new Error("MUST use domains when setting Keypair"));
        return;
      }
      if (!opts.email) {
        cb(new Error("MUST use email when setting Keypair"));
        return;
      }
      if (!opts.accountId) {
        cb(new Error("MUST use accountId when setting Keypair"));
        return;
      }



      if (!keypair.privateKeyJwk) {
        cb(new Error("MUST use privateKeyJwk when setting Keypair"));
        return;
      }
      if (!keypair.privateKeyPem) {
        cb(new Error("MUST use privateKeyPem when setting Keypair"));
        return;
      }
      if (!keypair.publicKeyPem) {
        cb(new Error("MUST use publicKeyPem when setting Keypair"));
        return;
      }



      var subject = opts.domains[0];

      opts.domains.forEach(function (domain) {
        memDb.certIndices[domain] = subject;
      });

      memDb.certKeypairs[subject] = keypair;
      /*
      {
        subject: subject
      , keypair: keypair
      };
      */

      cb(null, memDb.certKeypairs[subject]);
    }
    // Certificates
  , checkKeypair: function (opts, cb) {
      // opts.domains
      if (!opts.domains || !opts.domains.length) {
        cb(new Error("MUST use domains when checking Keypair"));
        return;
      }

      var domain = opts.domains[0];
      var subject = memDb.certIndices[domain];

      cb(null, memDb.certKeypairs[subject]);
    }



    // Certificates
  , set: function (opts, certs, cb) {
      // opts.domains
      // opts.email // optional
      // opts.accountId // optional

      // certs.privkey
      // certs.cert
      // certs.chain

      var index;
      var accountId;
      var account;
      var subject = certs.subject || opts.domains[0];
      var altnames = certs.altnames || opts.domains;
      var accountCerts;

      if (opts.accountId) {
        index = opts.accountId;
      }
      else if (opts.email) {
        index = opts.email;
      }
      else {
        cb(new Error("MUST supply email or accountId"));
        return;
      }

      accountId = memDb.accountIndices[index];
      account = memDb.accounts[accountId];

      if (!account) {
        cb(new Error("account must exist"));
      }

      accountId = memDb.accountIndices[index];
      if (!accountId) {
        cb(new Error("keypair was not previously set with email and keypair.publicKeyPem"));
        return;
      }

      memDb.certIndices[subject] = subject;
      altnames.forEach(function (altname) {
        memDb.certIndices[altname] = subject;
      });

      accountCerts = memDb.accountCerts[accountId] || {};
      accountCerts[subject] = subject;
      memDb.accountCerts[accountId] = accountCerts;

      memDb.certificates[subject] = certs;

      // SAVE to the database, index the email address, the accountId, and alias the domains
      cb(null, certs);
    }
    // Certificates
  , check: function (opts, cb) {
      // You will be provided one of these (which should be tried in this order)
      // opts.domains
      // opts.email // optional
      // opts.accountId // optional
      var subject;
      var subjects;
      var accountId;

      if (opts.domains) {
        subject = memDb.certIndices[opts.domains[0]];
        cb(null, memDb.certificates[subject]);
        return;
      }

      if (opts.accountId) {
        accountId = memDb.accountIndices[opts.accountId];
      }
      else if (opts.email) {
        accountId = memDb.accountIndices[opts.email];
      }

      subjects = memDb.accountCerts[accountId] || [];
      cb(null, subjects.map(function (subject) {
        subject = memDb.certIndices[subject];
        return memDb.certificates[subject] || null ;
      }));
    }

  };



  return {
    getOptions: function () {
      Object.keys(defaults).forEach(function (key) {
        if ('undefined' === typeof options[key]) {
          options[key] = defaults[key];
        }
      });

      // merge options with default settings and then return them
      return options;
    }
  , accounts: accounts
  , certificates: certificates
  };



};
