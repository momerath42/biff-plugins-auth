(ns com.ractiveware.biff-plugins-auth.plugins.monolith
  (:require
   [com.biffweb :as biff]
   [clj-http.client :as http]
   [clojure.string :as str]
   [rum.core :as rum]
   [xtdb.api :as xt]
   [buddy.hashers :as hashers]
   [com.ractiveware.repl :as repl]))

(defn passed-recaptcha? [{:keys [biff/secret biff.recaptcha/threshold params]
                          :or {threshold 0.5}}]
  (or (nil? (secret :recaptcha/secret-key))
      (let [{:keys [success score]}
            (:body
             (http/post "https://www.google.com/recaptcha/api/siteverify"
                        {:form-params {:secret (secret :recaptcha/secret-key)
                                       :response (:g-recaptcha-response params)}
                         :as :json}))]
        (and success (or (nil? score) (<= threshold score))))))

(defn new-link [{:keys [biff.auth/check-state
                        biff/base-url
                        biff/secret
                        anti-forgery-token]}
                email]
  (str base-url "/auth/verify-link/"
       (biff/jwt-encrypt
        (cond-> {:intent "signin"
                 :email email
                 :exp-in (* 60 60)}
          check-state (assoc :state (biff/sha256 anti-forgery-token)))
        (secret :biff/jwt-secret))))

(defn new-code [length]
  (let [rng (java.security.SecureRandom/getInstanceStrong)]
    (format (str "%0" length "d")
            (.nextInt rng (dec (int (Math/pow 10 length)))))))

(defn send-link! [{:keys [biff.auth/email-validator
                          biff.auth/get-user-id
                          biff/send-email
                          biff/db
                          params]
                   :as ctx}
                  email]
  (let [url (new-link ctx email)]
    (cond
     (not (email-validator ctx email))
     {:success false :error "invalid-email"}

     (not (send-email ctx
                      {:template :signin-link
                       :to email
                       :url url
                       :user-exists (get-user-id db email)}))
     {:success false :error "send-failed"}

     :else
     {:success true :email email})))

(defn verify-link [{:keys [biff.auth/check-state
                           biff/secret
                           path-params
                           params
                           anti-forgery-token]}]
  (let [{:keys [intent email state]} (-> (merge params path-params)
                                         :token
                                         (biff/jwt-decrypt (secret :biff/jwt-secret)))
        valid-state (= state (biff/sha256 anti-forgery-token))
        valid-email (= email (:email params))]
    (cond
     (not= intent "signin")
     {:success false :error "invalid-link"}

     (or (not check-state) valid-state valid-email)
     {:success true :email email}

     (some? (:email params))
     {:success false :error "invalid-email"}

     :else
     {:success false :error "invalid-state"})))

(defn send-code! [{:keys [biff.auth/email-validator
                          biff/db
                          biff/send-email
                          biff.auth/get-user-id
                          biff.auth/invite-required
                          biff.auth/use-invite!
                          params]
                   :as ctx}]
  (let [email (biff/normalize-email (:email params))
        code (new-code 6)
        user-id (delay (get-user-id db email))]
    (cond
      (not (passed-recaptcha? ctx))
      {:success false :error "recaptcha"}

      (not (email-validator ctx email))
      {:success false :error "invalid-email"}

      (not (send-email ctx
                       {:template :signin-code
                        :to email
                        :code code
                        :user-exists (some? @user-id)}))
      {:success false :error "send-failed"}

      :else
      {:success true :email email :code code :user-id @user-id})))

(defn verify-password [{:keys [biff.auth/password-checker
                               biff/db
                               biff.auth/get-user-id
                               params]
                        :as ctx}
                       user-id
                       email
                       password]
  (let [user (biff/lookup db :xt/id user-id)]
    (tap> {:fun :verify-password :email email
           :user-id user-id :user user
           :password password})
    (if (and (some? user)
             (password-checker ctx user password))
      {:success true :user user :email email}
      {:success false :error "incorrect-password"
       :user user :email email})))

(defn create-account! [{:keys [biff.auth/new-user-tx
                               biff.auth/enable-passwords
                               biff.auth/password-conforms?
                               biff.auth/get-user-id
                               biff/db]
                        :as ctx}
                       email & {:keys [password]}]
  (if (and (true? enable-passwords)
           ;; not entering a password is allowed by default:
           (some? password)
           (not (password-conforms? ctx password)))
    {:success false :error "nonconforming-password"}
    (let [tx (new-user-tx ctx email :password password)]
      (tap> {:fun :create-account! :tx tx :ctx ctx})
      (if (biff/submit-tx (assoc ctx :biff.xtdb/retry false) tx)
        (let [ctx (biff/merge-context ctx)]
          {:success true :user-id (get-user-id db email)})
        {:success false :error "user-insert"}))))

(defn error-redirect [params error]
  {:status 303
   :headers {"location"
             (str (:on-error params "/") "?error=" error)}})

;; coerce "" to nil, so it doesn't get inserted and is falsey
(defn normalize-password [params]
  (let [pw-param (:password params)]
    (if (empty? pw-param) nil pw-param)))

(defn validate-signup [{:keys [biff.auth/single-opt-in
                               biff.auth/invite-required
                               biff.auth/use-invite!
                               biff.auth/enable-passwords
                               biff.auth/get-user-id
                               biff/db
                               params]
                        :as ctx}
                       email]
  (let [existing-user-id (get-user-id db email)]
    (cond 
      (not (passed-recaptcha? ctx))
      {:success false :error "recaptcha"}
      
      (some? existing-user-id)
      (if-let [password (normalize-password params)]
        (if (verify-password ctx existing-user-id email password)
          {:success true :skip-link? true ;; treat it as a login
           :user-id existing-user-id} 
          {:success false :error "user-exists"})
        {:success true}) ;; treat it as a password-reset(ish)
      
      (true? invite-required)
      ;; note: this creates the user in the db, if single-opt-in (refactor?)
      (if (use-invite! ctx (:invite-code params) email)
        {:success true}
        {:success false :error "invalid-invite"})

      ;; essentially redundant (could pass the (sometimes nil) password in
      ;; the single-opt-in clause), but I prefer it for clarity
      (true? enable-passwords) 
      (let [password (normalize-password params)]
        (create-account! ctx email :password password))
      
      (true? single-opt-in)
      (create-account! ctx email)

      (false? single-opt-in)
      {:success true} ;; no-op

      ;; _should_ be exhaustive; if not, an exception is appropriate
      )))

;;; HANDLERS -------------------------------------------------------------------


(defn signup-handler [{:keys [biff.auth/get-user-id
                              biff.auth/app-path
                              biff.auth/enable-passwords
                              biff.auth/single-opt-in
                              biff/db
                              params
                              session]
                       :as ctx}]
  (assert (not (and enable-passwords (not single-opt-in)))
          "The combination of single-opt-in=false and enable-passwords=true is unsupported!")
  (let [email (biff/normalize-email (:email params))
        {:keys [success error skip-link? user-id]}
        (validate-signup ctx email)]
    (cond
      (and success skip-link?)
      {:status 303
       :headers {"location" app-path}
       :session (assoc session :uid user-id)}
      
      success
      (let [{:keys [success error]} (send-link! ctx email)]
        (if success
          {:status 303
           :headers {"location" app-path
                     ;; decided to just log them in, for my use-case
                     ;;(str "/link-sent?email=" email)
                     }
           :session (assoc session :uid user-id)}
          (error-redirect params error)))

      :else
      (error-redirect params error))))

(defn verify-link-handler [{:keys [biff.auth/app-path
                                   biff.auth/invalid-link-path
                                   biff.auth/new-user-tx
                                   biff.auth/get-user-id
                                   biff.auth/enable-passwords
                                   biff.auth/email-validated-tx
                                   biff.xtdb/node
                                   session
                                   params
                                   path-params]
                            :as req}]
  (let [{:keys [success error email]} (verify-link req)
        existing-user-id (when success (get-user-id (xt/db node) email))
        token (:token (merge params path-params))]
    (if (true? enable-passwords)
      (when (true? success)
        (assert existing-user-id
                "passwords enabled, but user-doc not found in verify-link-handler; note that single-opt-in must be true when using passwords")
        (tap> {:fun :verify-link-handler :req req :existing-user-id existing-user-id})
        (biff/submit-tx req (email-validated-tx req existing-user-id)))
      (when (and success (not existing-user-id))
        (biff/submit-tx req (new-user-tx req email))))
    {:status 303
     :headers {"location" (cond
                            success
                            app-path

                            (= error "invalid-state")
                            (str "/verify-link?token=" token)

                            (= error "invalid-email")
                            (str "/verify-link?error=incorrect-email&token=" token)

                            :else
                            invalid-link-path)}
     :session (cond-> session
                success (assoc :uid (or existing-user-id
                                        (get-user-id (xt/db node) email))))}))

(defn login-or-send-code-handler [{:keys [biff.auth/app-path
                                          biff.auth/single-opt-in
                                          biff.auth/enable-passwords
                                          biff.auth/new-user-tx
                                          biff.auth/get-user-id
                                          biff/db
                                          params
                                          session]
                                   :as ctx}]
  (let [email (biff/normalize-email (:email params))
        existing-user-id (get-user-id db email)
        password (:password params)]
    (tap> {:fun :login-or-send-code-handler
           :email email :existing-user-id existing-user-id
           :params params :password password})
    (cond
      (not (some? existing-user-id))
      ;; some would consider it bad practice to leak whether or not an account
      ;; exists, but I prefer the convenience of being told that's the problem,
      ;; and of not having a separate form for "forgot password"
      {:status 303
       :headers {"location" (str "/signin?error=no-account&email=" email)}}

      (and (true? enable-passwords)
           ;; if left blank, send a code instead
           (not (or (nil? password)
                    (empty? password))))
      (let [{:keys [success error user]}
            (verify-password ctx existing-user-id email password)]
        (tap> {:fun :login-or-send-code-handler :clause :password-check
               :email email :user user
               :params params :password (:password params)})
        (if success
          {:status 303
           :headers {"location" app-path}
           :session (assoc session :uid (:xt/id user))}
          {:status 303
           :headers {"location" (str "/signin?error=invalid-password&email=" email)}}))

      :else
      (let [{:keys [success error email code user-id]} (send-code! ctx)]
        (when success
          (biff/submit-tx (assoc ctx :biff.xtdb/retry false)
                          (concat [{:db/doc-type :biff.auth/code
                                    :db.op/upsert {:biff.auth.code/email email}
                                    :biff.auth.code/code code
                                    :biff.auth.code/created-at :db/now
                                    :biff.auth.code/failed-attempts 0}]
                                  (when (and single-opt-in (not user-id))
                                    (new-user-tx ctx email)))))
        {:status 303
         :headers {"location" (if success
                                (str "/verify-code?email=" (:email params))
                                (str (:on-error params "/") "?error=" error))}})
      )))

(defn verify-code-handler [{:keys [biff.auth/app-path
                                   biff.auth/new-user-tx
                                   biff.auth/get-user-id
                                   biff.xtdb/node
                                   biff/db
                                   params
                                   session]
                            :as req}]
  (let [email (biff/normalize-email (:email params))
        code (biff/lookup db :biff.auth.code/email email)
        success (and (passed-recaptcha? req)
                     (some? code)
                     (< (:biff.auth.code/failed-attempts code) 3)
                     (not (biff/elapsed? (:biff.auth.code/created-at code) :now 3 :minutes))
                     (= (:code params) (:biff.auth.code/code code)))
        existing-user-id (when success (get-user-id db email))
        tx (cond
            success
            (concat [[::xt/delete (:xt/id code)]]
                    (when-not existing-user-id
                      (new-user-tx req email)))

            (and (not success)
                 (some? code)
                 (< (:biff.auth.code/failed-attempts code) 3))
            [{:db/doc-type :biff.auth/code
              :db/op :update
              :xt/id (:xt/id code)
              :biff.auth.code/failed-attempts [:db/add 1]}])]
    (biff/submit-tx req tx)
    (if success
      {:status 303
       :headers {"location" app-path}
       :session (assoc session :uid (or existing-user-id
                                        (get-user-id db email)))}
      {:status 303
       :headers {"location" (str "/verify-code?error=invalid-code&email=" email)}})))

(defn signout [{:keys [session]}]
  {:status 303
   :headers {"location" "/"}
   :session (dissoc session :uid)})

;;; ----------------------------------------------------------------------------
;;;; default implementations of functions that may be overridden by config
;;; ----------------------------------------------------------------------------

(defn email-valid? [ctx email]
  (and email (re-matches #".+@.+\..+" email)))

(defn new-user-tx [ctx email & {:keys [invite-id password]}]
  (let [basics {:db/doc-type :user
                :db.op/upsert {:user/email email}
                :user/joined-at :db/now
                :user/email-validated false}
        invite-info (when invite-id {:user/invited-via invite-id})
        password-info (when password
                        {:user/password
                         (hashers/derive password {:alg :argon2id})})]
    [(merge basics invite-info password-info)]))

(defn get-user-id [db email]
  (biff/lookup-id db :user/email email))

#_(defn inc-invite-uses-tx-fn [ctx invite-code]
    (let [db (xtdb.api/db ctx)
          entity (xtdb.api/entity db invite-code)
          max-uses (:invite/max-uses entity)
          uses (:invite/uses entity)]
      (if (>= uses max-uses)
        false
        [[:xt/put (update entity :invite/uses inc)]])))

#_(defn use-invite! [db invite-code]
  (let [submitted-tx (xt/submit-tx db [[::xt/fn :inc-invite-uses
                                        invite-code]])]
    (try
      (xt/await-tx db submitted-tx) ; necessary? (I think so)
      (xt/tx-committed? db submitted-tx)
      (catch Exception e
        (println "use-invite! caught: " (.getMessage e))
        false))))

;; TODO: refactor and/or make clearer
(defn use-invite! [{:biff.auth/keys
                    [single-opt-in
                     new-user-tx
                     enable-passwords
                     password-conforms?
                     params]
                    :as ctx}
                   invite-code email]
  (let [password (normalize-password params)]
    (if (and (true? enable-passwords)
             password ;; entering a password is optional
             (not (password-conforms? ctx password)))
      false
      (let [submitted-tx
            (biff/submit-tx
             ctx
             (fn [{:keys [biff/db]}]
               (let [invite (biff/lookup db :invite/code invite-code)
                     invite-id (:xt/id invite)]
                 (when (and (some? invite)
                            (< (:invite/uses invite)
                               (:invite/max-uses invite)))
                   (let [tx (concat
                    [{:db/doc-type :invite
                      :xt/id invite-id
                      :db/op :update
                      :invite/uses [:db/add 1]}]
                    (when (true? single-opt-in)
                       (new-user-tx ctx email
                                    :invite-id invite-id
                                    :password password)))]
                     (tap> {:fun :use-invite!-fn :tx tx})
                     tx)))))]
        (some? submitted-tx)))))

(defn password-correct? [ctx user password]
  (tap> {:fun :password-correct? :user user :password password})
  (if-let [pw-hash (:user/password user)]
    (hashers/verify password pw-hash)
    false))

(defn password-conforms? [ctx password]
  ;; insert silly non-length-based requirements here
  ;; TODO? are there any characters we want to disallow for other reasons?
  ;; sql-injection won't work with biff, unless you changed quite a bit
  (tap> {:fun :password-conforms? :ctx ctx :password password})
  (let [l (count password)]
    (and (>= l 8)
         ;; having a maximum prevents using the password-hasher for
         ;; denial-of-service
         (<= l 64))))

(defn email-validated-tx [ctx user-id]
  [{:db/doc-type :user
    :db/op :update
    :xt/id user-id
    :user/email-validated true}])

;;; ----------------------------------------------------------------------------

(def default-options
  #:biff.auth{:app-path "/app"
              :invalid-link-path "/signin?error=invalid-link"
              :check-state true
              :new-user-tx new-user-tx
              :get-user-id get-user-id
              :single-opt-in true
              :invite-required false
              ;;:new-invite-tx new-invite-tx
              :use-invite! use-invite!
              :enable-passwords true
              :email-validated-tx email-validated-tx
              :email-validator email-valid?
              :password-checker password-correct?
              :password-conforms? password-conforms?
              :extra-schema
              {:invite/id :uuid
               :invite [:map ;;{closed true}
                        [:xt/id :invite/id]
                        [:invite/code :string]
                        [:invite/description :string]
                        [:invite/max-uses integer?]
                        [:invite/uses integer?]]}})

(defn wrap-options [handler options]
  (fn [req]
    (handler (merge options req))))

(defn plugin [options]
  (let [options* (merge default-options options)]
    {:schema (merge
              {:biff.auth.code/id :uuid
               :biff.auth/code [:map {:closed true}
                                [:xt/id :biff.auth.code/id]
                                [:biff.auth.code/email :string]
                                [:biff.auth.code/code :string]
                                [:biff.auth.code/created-at inst?]
                                [:biff.auth.code/failed-attempts integer?]]}
              (:biff.auth/extra-schema options*))
     ;; TODO? rename send-link/send-code routes?
     :routes [["/auth" {:middleware [[wrap-options options*]]}
               ["/send-link"          {:post signup-handler}]
               ["/verify-link/:token" {:get verify-link-handler}]
               ["/verify-link"        {:post verify-link-handler}]
               ["/send-code"          {:post login-or-send-code-handler}]
               ["/verify-code"        {:post verify-code-handler}]
               ["/signout"            {:post signout}]]]
     ;;:tx-fns {:inc-invite-uses (:inc-invite-uses-tx-fn options*)}
     }))

;; TODO? should this be part of the plugin or not?
(defn new-invite-tx [ctx code max-uses description]
  [{:db/doc-type :invite
    :db/op :create
    :invite/code code
    :invite/description description
    :invite/max-uses max-uses
    :invite/uses 0}])

(comment
  (let [ctx (repl/get-sys)]
    (biff/submit-tx ctx (new-invite-tx ctx "test" 10 "test invite code")))
  )

;;; FRONTEND HELPERS -----------------------------------------------------------

(def recaptcha-disclosure
  [:div {:style {:font-size "0.75rem"
                 :line-height "1rem"
                 :color "#4b5563"}}
   "This site is protected by reCAPTCHA and the Google "
   [:a {:href "https://policies.google.com/privacy"
        :target "_blank"
        :style {:text-decoration "underline"}}
    "Privacy Policy"] " and "
   [:a {:href "https://policies.google.com/terms"
        :target "_blank"
        :style {:text-decoration "underline"}}
    "Terms of Service"] " apply."])

(defn recaptcha-callback [fn-name form-id]
  [:script
   (biff/unsafe
    (str "function " fn-name "(token) { "
         "document.getElementById('" form-id "').submit();"
         "}"))])


