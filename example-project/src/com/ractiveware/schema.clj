(ns com.ractiveware.schema)

(def schema
  {:user/id :uuid
   :user/foo :string
   :user/bar :string
   :user/email :string
   :user/email-validated :boolean
   :user/password :string
   :user/joined-at inst?
   :user [:map ;;{:closed true}
          [:xt/id :user/id]
          :user/email
          :user/joined-at
          [:user/email-validated {:optional true}]
          [:user/password {:optional true}]
          [:user/foo {:optional true}]
          [:user/bar {:optional true}]]

   :msg/id :uuid
   :msg/user :user/id
   :msg/text :string
   :msg/sent-at inst?
   :msg [:map {:closed true}
         [:xt/id :msg/id]
         :msg/user
         :msg/text
         :msg/sent-at]})

(def features
  {:schema schema})
