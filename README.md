# biff-plugins-auth
Third-party auth plugins for [Biff](https://biffweb.com); currently one monolith with optional password and invite-code support

# Usage
1. Add `com.ractiveware/biff-plugins-auth {:git/url "https://github.com/momerath42/biff-plugins-auth", :tag "v0.1.1"}` to your deps.edn
2. Require `[com.ractiveware.biff-plugins-auth :as bpa]` in your biff project's system-setup namespace (generally the eponymous one)
3. Replace `(biff/authentication-plugin {})` in your `features` vector with `(bpa/monolith {})`
4. If enabling passwords (as is the default), modify your project's `schema.clj` to include :user/password and :user/email-validated fields

# Options
See the monolith docstring for modified and additional options: [src/com/ractiveware/biff_plugins_auth.clj](https://github.com/momerath42/biff-plugins-auth/blob/main/src/com/ractiveware/biff_plugins_auth.clj)

# Authentication Flow
This is how the flow works, with invites and passwords enabled.  Note that I'm allowing use of signup and signin pages to request a link/code, and that the user is immediately logged in when providing a valid password

![authentication flow](./auth-flow.svg)
