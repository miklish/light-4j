/*
 * Copyright (c) 2016 Network New Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.networknt.jwtcert;

import com.networknt.config.Config;
import com.networknt.handler.Handler;
import com.networknt.handler.MiddlewareHandler;
import com.networknt.utility.ModuleRegistry;
import io.undertow.Handlers;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.util.Headers;
import io.undertow.util.HttpString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;

import com.networknt.security.JwtHelper;

import java.util.*;

/**
 * Overview
 *
 *   This is a handler that compares the hostname in the X.509 certificate of the TLS session with the hostname in
 *   the JWT. It does not work with other certificate types.
 *
 * Where to get hostname from X.509 certificate
 *
 *   The policy of this handler is as follows:
 *
 *   1. If the SAN is present, then accept iff the hostname of the JWT is one of the entries in the dnsName entries in
 *      the SAN.
 *   2. If the SAN is not present, then accept iff the CN value of the Subject DN matches the hostname of the JWT.
 *
 *   References
 *
 *     Discussion
 *       https://stackoverflow.com/questions/25970714/invalid-common-name-when-using-a-san-certificate
 *       https://stackoverflow.com/questions/5935369/ssl-how-do-common-names-cn-and-subject-alternative-names-san-work-together
 *
 *     HTTPS RFC on CNs vs SANs
 *       RFC2818 : HTTP Over TLS    : https://www.ietf.org/rfc/rfc2818.txt
 *       RFC6125 : Service Identity : https://www.ietf.org/rfc/rfc6125.txt
 *
 *     SAN Semantics (OIDs)
 *       RFC5280 : X.509 PKI Certificate and CRL Profile : https://tools.ietf.org/html/rfc5280#section-4.2.1.6
 *
 *     DN string formats
 *       RFC1779 : https://www.ietf.org/rfc/rfc1779.txt
 *       RFC2253 : https://www.ietf.org/rfc/rfc2253.txt
 *
 * @author Michael N. Christoff
 * @since 1.5.21
 */
public class JwtCertHandler implements MiddlewareHandler {
    static final Logger logger = LoggerFactory.getLogger(JwtCertHandler.class);

    public static final String CONFIG_NAME = "jwtcert";
    public static final String ENABLED = "enabled";
    public static final Integer DNS_NAME_OID = Integer.valueOf(2);

    public static final Map<String, Object> config = Config.getInstance().getJsonMapConfig(CONFIG_NAME);

    private volatile HttpHandler next;

    public JwtCertHandler() {}

    /**
     * Check iterate the configuration on both request and response section and update
     * headers accordingly.
     *
     * @param exchange HttpServerExchange
     * @throws Exception Exception
     */
    @Override
    public void handleRequest(final HttpServerExchange exchange) throws Exception
    {
        // get JWT from Authorization header field
        String jwt = getJWTFromAuthorization(exchange);
        if(jwt == null || jwt.isEmpty()) {
            logger.info("Failure: No JWT found in Authorization Header field");
            return;
        }
        logger.info("JWT:\n{}", jwt);

        String jwtHostname = getJWTHostname(jwt);
        if(jwtHostname == null || jwtHostname.isEmpty()) {
            logger.info("Failure: No hostname found in JWT");
            return;
        }
        else
            logger.info("JWT hostname found: {}", jwtHostname);

        javax.net.ssl.SSLSession ssls = exchange.getConnection().getSslSession();
        if(ssls == null) {
            logger.info("Failure: No SSL Session");
            return;
        }

        try {
            //java.security.cert.Certificate[] certs = ssls.getPeerCertificates();
            java.security.cert.Certificate[] certs = ssls.getLocalCertificates();
            if(certs == null || certs.length == 0) {
                logger.error("Failure: No certificates found in TLS Session");
                return;
            }

            // Per API docs: first cert is the peer's cert (not CA certs)
            java.security.cert.Certificate cert = certs[0];

            logger.info("Certificate type :: {}", cert.getType());
            if(!(cert instanceof X509Certificate)) {
                logger.error("Failure: Certificate is not X.509");
                return;
            }

            X509Certificate x509Cert = (X509Certificate) cert;

            // get dnsName's from SAN
            logger.info("Checking Subject Alt Names :: ");
            Set<String> sanDnsNames = getSanDnsNames(x509Cert);
            if(sanDnsNames != null)
            {
                if (sanDnsNames.contains(jwtHostname)) {
                    logger.info("Success: JWT hostname found in SAN of certificate");
                    Handler.next(exchange, next);
                    return;
                }
                else {
                    logger.info("Failure: JWT hostname not found in SAN of certificate");
                    return;
                }
            }

            // no SAN found, so check CN of Subject DN
            String dn = getCN(x509Cert);
            if(dn != null && !dn.isEmpty() && dn.equals(jwtHostname)) {
                logger.info("Success: JWT hostname found in CN of certificate Subject DN");
                Handler.next(exchange, next);
                return;
            }

            logger.info("Failure: Could not find JWT hostname " + jwtHostname + "in X.509");
            return;

            //} catch(javax.net.ssl.SSLPeerUnverifiedException sslunv) {    // only thrown when getting peer cert
        } catch(Exception sslunv) {                                     // use when acquiring local cert
            logger.info("SSLPeerUnverifiedException!");
        }
    }

    private String getJWTFromAuthorization(HttpServerExchange exchange) {
        return JwtHelper.getJwtFromAuthorization(
                exchange.getRequestHeaders().getFirst(Headers.AUTHORIZATION));
    }


    private String getJWTHostname(String jwt) {
        // extract hostname from jwt
        String extractedJwtHostname = "IMST.dev2.cibc.com-";

        return extractedJwtHostname.trim().toLowerCase();
    }

    /*
        Returns null only if no SAN found
        - in this case can consult CN for hostname

        If SAN is non-null but does not contain matching dnsName,
        then it is an error--do no consult CN

        Trims and converts to lowercase all entries
     */
    private Set<String> getSanDnsNames(X509Certificate x509cert)
            throws CertificateParsingException
    {
        Collection<List<?>> altNamesListCollection = x509cert.getSubjectAlternativeNames();
        Set<String> sanDnsNames = new HashSet<>();
        if(altNamesListCollection != null && altNamesListCollection.size() > 0)
        {
            // Each entry is a List whose first entry is an Integer (the name type, 0-8) and whose
            // second entry is a String or a byte array. Type 2 denotes a dnsName Object ID (OID)
            logger.info("\tSAN names below:");
            for(List<?> altNameList : altNamesListCollection)
                if (altNameList.size() == 2) {
                    Integer oid = (Integer) altNameList.get(0);

                    // == works on Integer objects between -127 and 128
                    if (oid != DNS_NAME_OID || !(altNameList.get(1) instanceof String)) {
                        continue;
                    }

                    String dnsName = (String) altNameList.get(1);
                    sanDnsNames.add(dnsName.trim().toLowerCase());
                    logger.info("\t\t{}", dnsName);
                } else
                    logger.info("\t\tList element count <> 2!");
        }
        else {
            logger.info("\tNo Subject Alt Name section!");
            return null;
        }

        return sanDnsNames;
    }

    /*
        Trims and converts to lowercase all urls
     */
    private String getCN(X509Certificate x509Cert)
    {
        String subjectDN = x509Cert.getSubjectX500Principal().getName(X500Principal.RFC2253);
        if(subjectDN == null || subjectDN.isEmpty()) return null;

        String[] parts = subjectDN.split(",");
        if(parts.length < 2 || parts[0].equals(subjectDN)) return null;

        for(int i = 0; i < parts.length; ++i)
        {
            String[] pair = parts[i].split("=");
            if(pair.length < 2 || pair[0].equals(parts[i])) continue;

            logger.info("\tPair :: {} -> {}", pair[0], pair[1]);

            if(pair[0].trim().equalsIgnoreCase("CN"))
                return pair[1].trim().toLowerCase();
        }
        return null;
    }

    @Override
    public HttpHandler getNext() {
        return next;
    }

    @Override
    public MiddlewareHandler setNext(final HttpHandler next) {
        Handlers.handlerNotNull(next);
        this.next = next;
        return this;
    }

    @Override
    public boolean isEnabled() {
        Object object = config.get(JwtCertHandler.ENABLED);
        return object != null && (Boolean) object;
    }

    @Override
    public void register() {
        ModuleRegistry.registerModule(JwtCertHandler.class.getName(), Config.getInstance().getJsonMapConfigNoCache(CONFIG_NAME), null);
    }

    private Map<String,String> getDNMap(String subjectDN)
    {
        Map<String,String> map = new HashMap<>();
        if(subjectDN == null || subjectDN.isEmpty()) return map;

        String[] parts = subjectDN.split(",");
        if(parts.length < 2 || parts[0].equals(subjectDN)) return map;

        for(int i = 0; i < parts.length; ++i)
        {
            String[] pair = parts[i].split("=");
            if(pair.length < 2 || pair[0].equals(parts[i])) continue;
            map.put(pair[0].toLowerCase(), pair[1]);
        }
        return map;
    }
}


    /*
    @Override
    public void handleRequest(final HttpServerExchange exchange) throws Exception {
        // handle request header
        Map<String, Object> requestHeaderMap = (Map<String, Object>)config.get(REQUEST);
        if(requestHeaderMap != null) {
            List<String> requestHeaderRemove = (List<String>)requestHeaderMap.get(REMOVE);
            if(requestHeaderRemove != null) {
                requestHeaderRemove.forEach(s -> exchange.getRequestHeaders().remove(s));
            }
            Map<String, String> requestHeaderUpdate = (Map<String, String>)requestHeaderMap.get(UPDATE);
            if(requestHeaderUpdate != null) {
                requestHeaderUpdate.forEach((k, v) -> exchange.getRequestHeaders().put(new HttpString(k), v));
            }
        }

        // handle response header
        Map<String, Object> responseHeaderMap = (Map<String, Object>)config.get(RESPONSE);
        if(responseHeaderMap != null) {
            List<String> responseHeaderRemove = (List<String>)responseHeaderMap.get(REMOVE);
            if(responseHeaderRemove != null) {
                responseHeaderRemove.forEach(s -> exchange.getResponseHeaders().remove(s));
            }
            Map<String, String> responseHeaderUpdate = (Map<String, String>)responseHeaderMap.get(UPDATE);
            if(responseHeaderUpdate != null) {
                responseHeaderUpdate.forEach((k, v) -> exchange.getResponseHeaders().put(new HttpString(k), v));
            }
        }
    }
    */
