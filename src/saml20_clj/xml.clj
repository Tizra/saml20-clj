(ns saml20-clj.xml
  (:require hiccup.core
            hiccup.page
            [clojure.java.io :as io]
            [clojure.data.codec.base64 :as b64]
            [saml20-clj.shared :as saml-shared])
  (:import [java.security KeyStore]
           [java.security.cert X509Certificate]
           [java.io ByteArrayInputStream]
           [javax.xml.crypto KeySelector]
           [javax.xml.crypto.dsig XMLSignature XMLSignatureFactory]
           [javax.xml.crypto.dsig.dom DOMValidateContext]
           [javax.xml.parsers DocumentBuilderFactory DocumentBuilder]
           [org.opensaml.xml.security.keyinfo StaticKeyInfoCredentialResolver]
           [org.opensaml.xml.encryption InlineEncryptedKeyResolver]
           [org.apache.xml.security Init]
           [org.apache.xml.security.utils Constants ElementProxy]
           [org.apache.xml.security.transforms Transforms]
           [org.apache.xml.security.c14n Canonicalizer]
           [org.w3c.dom Document Node NodeList]
           [org.apache.xml.security.c14n Canonicalizer]
           [org.opensaml.xml.security.x509 BasicX509Credential]
           [org.opensaml.saml2.encryption Decrypter]))

(defn make-xml-string
  "Creates an XML string using hiccup."
  [structure]
  (str
    (hiccup.page/xml-declaration "UTF-8")
    (hiccup.core/html structure)))

(defn singleton-key-selector
  "Always uses a provided key as a selector."
  [jkey]
  (KeySelector/singletonKeySelector jkey))

(defn ^DocumentBuilder new-doc-builder
  []
  (let [doc (DocumentBuilderFactory/newInstance)]
    (.setNamespaceAware doc true)
    (.newDocumentBuilder doc)))

(defn ^XMLSignatureFactory new-xml-sig-factory
  []
  (XMLSignatureFactory/getInstance "DOM"))

(defn ^Document str->xmldoc
  [parsable-str]
  (let [document (new-doc-builder)]
    (.parse document (saml-shared/str->inputstream parsable-str))))

(defn xmlsig-from-xmldoc
  [^Document xmldoc]
  (let [nodes (.getElementsByTagNameNS xmldoc XMLSignature/XMLNS "Signature")]
    ;;; Zero nodes means that we can't find a XML signature.
    (if (= (.getLength nodes) 0)
      ;;(throw (Throwable. "This XML document has no signature to verify."))
      nil
      (.item nodes 0)))) ;;; Take the first node.

(defn ^DOMValidateContext get-dom-context
  [^KeySelector kv-selector ^Node signature-node]
  (DOMValidateContext. kv-selector signature-node))

(defn validate-xml-signature
  "Checks if this XML document's signature is valid using the supplied certificate"
  [xml-string cert-string]
  (let [sig-factory (new-xml-sig-factory)
        public-key (saml-shared/jcert->public-key (saml-shared/certificate-x509 cert-string))
        xmldoc (str->xmldoc xml-string)
        xml-sig-node (xmlsig-from-xmldoc xmldoc)
        validate-signature #(let [context (get-dom-context (singleton-key-selector public-key) xml-sig-node)
                                  signature (.unmarshalXMLSignature sig-factory context)]
                              (.validate signature context))]
    (if xml-sig-node (validate-signature)
      true)))

(defn dom-node->str [dom-node]
  (let [canonicalizer (Canonicalizer/getInstance Canonicalizer/ALGO_ID_C14N_EXCL_OMIT_COMMENTS)]
    (String. (.canonicalizeSubtree canonicalizer dom-node))))

(defn- ^KeyStore load-key-store
  [^String keystore-filename ^String keystore-password]
  (when (and (not (nil? keystore-filename))
             (.exists (io/as-file keystore-filename)))
    (with-open [is (clojure.java.io/input-stream keystore-filename)]
      (doto (KeyStore/getInstance "PKCS12")
        (.load is (.toCharArray keystore-password))))))

(defn get-certificate-b64 [keystore-filename keystore-password ^String cert-alias]
  (let [^bytes b (some-> (load-key-store keystore-filename keystore-password)
                (.getCertificate cert-alias)
                (.getEncoded)
                b64/encode)]
    (String. b saml-shared/charset-format)))

(defn make-saml-signer
  [keystore-filename ^String keystore-password ^String key-alias]
  (when keystore-filename
    (Init/init)
    (ElementProxy/setDefaultPrefix Constants/SignatureSpecNS "")
    (let [ks (load-key-store keystore-filename keystore-password)
          private-key (.getKey ks key-alias (.toCharArray keystore-password))
          ^X509Certificate cert (.getCertificate ks key-alias)
          sig-algo (case (.getAlgorithm private-key)
                     "DSA" org.apache.xml.security.signature.XMLSignature/ALGO_ID_SIGNATURE_DSA
                     org.apache.xml.security.signature.XMLSignature/ALGO_ID_SIGNATURE_RSA)]
      ;; https://svn.apache.org/repos/asf/santuario/xml-security-java/trunk/samples/org/apache/xml/security/samples/signature/CreateSignature.java
      ;; http://stackoverflow.com/questions/2052251/is-there-an-easier-way-to-sign-an-xml-document-in-java
      ;; Also useful: http://www.di-mgt.com.au/xmldsig2.html
      (fn sign-xml-doc [xml-string]
        (let [xmldoc (str->xmldoc xml-string)
              transforms (doto (new Transforms xmldoc)
                           (.addTransform Transforms/TRANSFORM_ENVELOPED_SIGNATURE)
                           (.addTransform Transforms/TRANSFORM_C14N_EXCL_OMIT_COMMENTS))
              sig (new org.apache.xml.security.signature.XMLSignature xmldoc nil sig-algo
                       Canonicalizer/ALGO_ID_C14N_EXCL_OMIT_COMMENTS)
              canonicalizer (Canonicalizer/getInstance Canonicalizer/ALGO_ID_C14N_EXCL_OMIT_COMMENTS)]
          (.. xmldoc
              (getDocumentElement)
              (appendChild (.getElement sig)))
          (doto ^org.apache.xml.security.signature.XMLSignature sig
            (.addDocument "" transforms Constants/ALGO_ID_DIGEST_SHA1)
            (.addKeyInfo cert)
            (.addKeyInfo (.getPublicKey cert))
            (.sign private-key))
          (String. (.canonicalizeSubtree canonicalizer xmldoc) "UTF-8"))))))

(defn ^Decrypter make-saml-decrypter
  [keystore-filename ^String keystore-password ^String key-alias]
  (when keystore-filename
    (let [ks (load-key-store keystore-filename keystore-password)
          private-key (.getKey ks key-alias (.toCharArray keystore-password))
          decryption-cred (doto (new BasicX509Credential)
                            (.setPrivateKey private-key))
          decrypter (new Decrypter
                         nil
                         (new StaticKeyInfoCredentialResolver decryption-cred)
                         (new InlineEncryptedKeyResolver))]
      decrypter)))

