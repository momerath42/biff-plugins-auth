(ns com.ractiveware.biff-plugins-auth
  (:require
   [com.ractiveware.biff-plugins-auth.plugins.monolith :as mono]))

(defn monolith
  "see biff's authentication-plugin docs for the common functionality.

  ----- Common Options Modified: -----
  
  :biff.auth/single-opt-in
  ------------------------
  Default: false

  This is a standard option from biff's plugin, with a different default. It
  will probably be removed in password-supporting non-monoliths later. For now,
  you can set it to true and enable invites, but it's mutually exclusive with
  enable-passwords.

  :biff.auth/new-user-tx
  ----------------------
  Default: a bit much to paste in a docstring; see the source. Optional
  parameters have been added!
              
              (fn [ctx email & {:keys [invite-id password]}]

  If you happen to be overriding the default, in the official plugin, you'll get
  a \"Wrong number of args (4) passed to: com.ractiveware/fn--<some-number>\"
  error, until you change your function's signature to match.


  ----- Additional Options: -----

  :biff.auth/invite-required
  --------------------------
  Default: false

  If true, signup requires an `invite-code` param, which the `use-invite!`
  function is meant to make use of. The default implementation expects the
  application to insert :invite documents into xtdb; the schema is
  described (and can be overridden) with the `extra-schema` option.

  :biff.auth/use-invite!
  ----------------------
  Default: a bit much to paste in a docstring, and likely to be refactored; see
  the source.  Here are the expected parameters:
              (fn [{:biff.auth/keys
                    [single-opt-in
                     new-user-tx
                     enable-passwords
                     password-conforms?
                     params]
                    :as ctx}
                   invite-code email]

  :biff.auth/enable-passwords
  ---------------------------
  Default: true
  
  You're probably using this plugin for passwords, and they're actually
  optional, even when this is true. The one caveat is that the combination of
  single-opt-in=false and enabled-passwords=true is currently unsupported, as an
  assert exception will inform you.

  :biff.auth/password-checker
  ---------------------------
  Default: (fn [ctx user password]
             (if-let [pw-hash (:user/password user)]
               (hashers/verify password pw-hash)
               false))

  Where `hashers` is the buddy.hashers library. The main reason to override this
  would be if your :user schema is different.

  :biff.auth/password-conforms?
  -----------------------------
  Default: (fn [ctx password]
             (let [l (count password)]
               (and (>= l 8)
                    (<= l 64))))

  Your basic password-acceptability test; see the code for notes.

  :biff.auth/extra-schema
  -----------------------
  Default: {:invite/id :uuid
            :invite [:map ;;{closed true}
                     [:xt/id :invite/id]
                     [:invite/code :string]
                     [:invite/description :string]
                     [:invite/max-uses integer?]
                     [:invite/uses integer?]]}

  The default is an invite schema which corresponds to the default
  `use-invite!`.

  :biff.auth/email-validated-tx
  -----------------------------
  Default: (fn [ctx user-id]
             [{:db/doc-type :user
               :db/op :update
               :xt/id user-id
               :user/email-validated true}]

  Given the single-opt-in=true requirement of password support, this update is
  applied when the emailed link is clicked, so you can require that within your
  app. Note that this default requires your application's user schema to contain
  the :user/email-validated field, which biff templates do not have by default.
  Something less surprising may be done in the future.
  "
  [{:biff.auth/keys
    [app-path
     invalid-link-path
     check-state
     new-user-tx
     get-user-id
     single-opt-in
     invite-required
     use-invite!
     enable-passwords
     email-validated-tx
     email-validator
     password-checker
     password-conforms?
     extra-schema]
    :as plugin-opts}]
  
  (mono/plugin plugin-opts))

