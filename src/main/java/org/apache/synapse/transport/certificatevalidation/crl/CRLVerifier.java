/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *   * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
package org.apache.synapse.transport.certificatevalidation.crl;

import java.io.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.*;
import org.apache.synapse.transport.certificatevalidation.*;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.*;
import java.util.*;
import javax.naming.*;
import javax.naming.directory.*;

/**
 * This is used to verify a certificate is revoked or not by using the Certificate Revocation List published
 * by the CA.
 */
public class CRLVerifier implements RevocationVerifier {

    private CRLCache cache;
    private static final Log log = LogFactory.getLog(CRLVerifier.class);

    public CRLVerifier(CRLCache cache) {
        this.cache = cache;
    }

    /**
     * Checks revocation status (Good, Revoked) of the peer certificate. IssuerCertificate can be used
     * to check if the CRL URL has the Issuers Domain name. But this is not implemented at the moment.
     *
     * @param peerCert   peer certificate
     * @param issuerCert issuer certificate of the peer. not used currently.
     * @return revocation status of the peer certificate.
     * @throws CertificateVerificationException
     *
     */
    public RevocationStatus checkRevocationStatus(X509Certificate peerCert, X509Certificate issuerCert)
            throws CertificateVerificationException {

        List<String> list = getCrlDistributionPoints(peerCert);
        //check with distributions points in the list one by one. if one fails go to the other.
        for (String crlUrl : list) {
            log.debug("Trying to get CRL for URL: " + crlUrl);

            if (cache != null) {
                X509CRL x509CRL = cache.getCacheValue(crlUrl);
                if (x509CRL != null) {
                    //If cant be casted, we have used the wrong cache.
                    RevocationStatus status = getRevocationStatus(x509CRL, peerCert);
                    log.debug("CRL taken from cache....");
                    return status;
                }
            }

            //todo: Do we need to check if URL has the same domain name as issuerCert?
            //todo: What if this certificate is Unknown?????
            try {
                X509CRL x509CRL = downloadCRL(crlUrl);
                if (x509CRL != null) {
                    if (cache != null)
                        cache.setCacheValue(crlUrl, x509CRL);
                    return getRevocationStatus(x509CRL, peerCert);
                }
            } catch (Exception e) {
                log.debug("Either url is bad or cant build X509CRL. So check with the next url in the list.", e);
            }
        }
        throw new CertificateVerificationException("Cannot check revocation status with the certificate");
    }

    private RevocationStatus getRevocationStatus(X509CRL x509CRL, X509Certificate peerCert) {
        if (x509CRL.isRevoked(peerCert)) {
            return RevocationStatus.REVOKED;
        } else {
            return RevocationStatus.GOOD;
        }
    }
     /**
     * Downloads CRL from given URL. Supports http, https, ftp and ldap based URLs.
     */
    protected  X509CRL downloadCRL(String crlURL) throws IOException,
            CertificateException, CRLException,
            CertificateVerificationException, NamingException {
        if (crlURL.startsWith("http://") || crlURL.startsWith("https://")
                || crlURL.startsWith("ftp://")) {
            return downloadCRLFromWeb(crlURL);
        } else if (crlURL.startsWith("ldap://")) {
            return downloadCRLFromLDAP(crlURL);
        } else {
            throw new CertificateVerificationException(
                    "Can not download CRL from certificate " +
                            "distribution point: " + crlURL);
        }
    }
    
   /**
     * Downloads a CRL from given LDAP url, e.g.
     * ldap://ldap.infonotary.com/dc=identity-ca,dc=infonotary,dc=com
     */
    private X509CRL downloadCRLFromLDAP(String ldapURL)
            throws CertificateException, NamingException, CRLException,
            CertificateVerificationException {
        Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY,
                "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapURL);

        DirContext ctx = new InitialDirContext(env);
        Attributes avals = ctx.getAttributes("");
        javax.naming.directory.Attribute aval = avals.get("certificateRevocationList;binary");
        byte[] val = (byte[]) aval.get();
        if ((val == null) || (val.length == 0)) {
            throw new CertificateVerificationException(
                    "Can not download CRL from: " + ldapURL);
        } else {
            InputStream inStream = new ByteArrayInputStream(val);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509CRL) cf.generateCRL(inStream);
        }
    }
    /**
     * Downloads a CRL from given HTTP/HTTPS/FTP URL, e.g.
     * http://crl.infonotary.com/crl/identity-ca.crl
     */
    private X509CRL downloadCRLFromWeb(String crlURL)
            throws MalformedURLException, IOException, CertificateException, CRLException  {
        InputStream crlStream = null;
        try {
            URL url = new URL(crlURL);
            crlStream = url.openStream();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509CRL) cf.generateCRL(crlStream);
        } finally {
            if (crlStream != null) {
                try {
                    crlStream.close();
                } catch (Exception ignore) {
                }
            }
        }
    }

    /**
     * Extracts all CRL distribution point URLs from the "CRL Distribution Point"
     * extension in a X.509 certificate. If CRL distribution point extension is
     * unavailable, returns an empty list.
     */
    private List<String> getCrlDistributionPoints(X509Certificate cert)
            throws CertificateVerificationException {

        //Gets the DER-encoded OCTET string for the extension value for CRLDistributionPoints
        byte[] crlDPExtensionValue = cert.getExtensionValue(X509Extensions.CRLDistributionPoints.getId());
        if (crlDPExtensionValue == null)
            throw new CertificateVerificationException("Certificate doesn't have CRL Distribution points");
        //crlDPExtensionValue is encoded in ASN.1 format.
        ASN1InputStream asn1In = new ASN1InputStream(crlDPExtensionValue);
        //DER (Distinguished Encoding Rules) is one of ASN.1 encoding rules defined in ITU-T X.690, 2002, specification.
        //ASN.1 encoding rules can be used to encode any data object into a binary file. Read the object in octets.
        CRLDistPoint distPoint;
        try {
            DEROctetString crlDEROctetString = (DEROctetString) asn1In.readObject();
            //Get Input stream in octets
            ASN1InputStream asn1InOctets = new ASN1InputStream(crlDEROctetString.getOctets());
            DERObject crlDERObject = asn1InOctets.readObject();
            distPoint = CRLDistPoint.getInstance(crlDERObject);
        } catch (IOException e) {
            throw new CertificateVerificationException("Cannot read certificate to get CRL urls", e);
        }

        List<String> crlUrls = new ArrayList<String>();
        //Loop through ASN1Encodable DistributionPoints
        for (DistributionPoint dp : distPoint.getDistributionPoints()) {
            //get ASN1Encodable DistributionPointName
            DistributionPointName dpn = dp.getDistributionPoint();
            if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
                //Create ASN1Encodable General Names
                GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
                // Look for a URI
                //todo: May be able to check for OCSP url specifically.
                for (GeneralName genName : genNames) {
                    if (genName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        //DERIA5String contains an ascii string.
                        //A IA5String is a restricted character string type in the ASN.1 notation
                        String url = DERIA5String.getInstance(genName.getName()).getString().trim();
                        crlUrls.add(url);
                    }
                }
            }
        }

        if (crlUrls.isEmpty())
            throw new CertificateVerificationException("Cant get CRL urls from certificate");

        return crlUrls;
    }
}
