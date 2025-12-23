(defproject saml20-clj "0.1.6-tizra-10"
  :description "Basic SAML 2.0 library for SSO."
  :repositories [[shibboleth "https://build.shibboleth.net/maven/releases/"]]
  :url "https://github.com/Tizra/saml20-clj"
  :license {:name "Eclipse Public License", :url "http://www.eclipse.org/legal/epl-v10.html"}
  :source-paths ["src"]
  :dependencies [[org.clojure/clojure "1.11.2"]
                 [clj-time "0.15.2"]
                 [ring "1.6.3"]
                 [org.apache.santuario/xmlsec "4.0.4"]
                 [javax.xml.bind/jaxb-api "2.3.1"]
                 [org.opensaml/opensaml "2.6.4"]
                 [org.clojure/tools.reader "1.5.2"]
                 [org.clojure/data.xml "0.2.0-alpha9"]
                 [org.clojure/data.codec "0.1.1"]
                 [org.clojure/data.zip "0.1.3"]]
  :pedantic :warn
  :profiles {:dev {},
             :test {:source-paths ["dev" "test"],
                    :dependencies [[nrepl "1.5.1"]
                                   [org.vlacs/helmsman "1.0.0-alpha5"]
                                   [hiccup "2.0.0"]
                                   [compojure "1.5.0"]
                                   [http-kit "2.2.0"]]}})
