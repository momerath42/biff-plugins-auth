(ns com.ractiveware
  (:require [com.biffweb :as biff]
            [com.ractiveware.email :as email]
            [com.ractiveware.feat.app :as app]
            [com.ractiveware.feat.home :as home]
            [com.ractiveware.feat.worker :as worker]
            [com.ractiveware.schema :as schema]
            [com.ractiveware.biff-plugins-auth :as bpa]
            [clojure.test :as test]
            [clojure.tools.logging :as log]
            [malli.core :as malc]
            [malli.registry :as malr]
            [nrepl.cmdline :as nrepl-cmd]
            [portal.api :as portal]))

(def features
  [app/features
   (bpa/monolith {:biff.auth/invite-required true})
   home/features
   schema/features
   worker/features])

(def routes [["" {:middleware [biff/wrap-site-defaults]}
              (keep :routes features)]
             ["" {:middleware [biff/wrap-api-defaults]}
              (keep :api-routes features)]])

(def handler (-> (biff/reitit-handler {:routes routes})
                 biff/wrap-base-defaults))

(def static-pages (apply biff/safe-merge (map :static features)))

(defn generate-assets! [sys]
  (biff/export-rum static-pages "target/resources/public")
  (biff/delete-old-files {:dir "target/resources/public"
                          :exts [".html"]}))

(defn on-save [sys]
  (biff/add-libs)
  (biff/eval-files! sys)
  (generate-assets! sys)
  (test/run-all-tests #"com.ractiveware.test.*"))

(def malli-opts
  {:registry (malr/composite-registry
              malc/default-registry
              (apply biff/safe-merge
                     (keep :schema features)))})

(defn use-portal [{:keys [com.ractiveware/portal] :as system}]
  (let [new-sys (assoc system :com.ractiveware/portal (portal/open {:theme :portal.colors/zerodark}))]
    (add-tap #'portal/submit)
    new-sys))

(def components
  [biff/use-config
   biff/use-secrets
   biff/use-xt
   biff/use-queues
   biff/use-tx-listener
   biff/use-wrap-ctx
   biff/use-jetty
   biff/use-chime
   (biff/use-when
    :com.ractiveware/enable-beholder
    biff/use-beholder)
   (biff/use-when
    :com.ractiveware/enable-portal
    use-portal)])

(defn start []
  (let [ctx (biff/start-system
             {:com.ractiveware/chat-clients (atom #{})
              :biff/send-email #'email/send-email
              :biff/features #'features
              :biff/after-refresh `start
              :biff/handler #'handler
              :biff/malli-opts #'malli-opts
              :biff.beholder/on-save #'on-save
              :biff.xtdb/tx-fns biff/tx-fns
              :biff/components components})]
    (generate-assets! ctx)
    (log/info "Go to" (:biff/base-url ctx))))

(defn -main [& args]
  (start)
  (apply nrepl-cmd/-main args))
