/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.certificate.ocsp;

import static de.rub.nds.tlsattacker.core.certificate.ExtensionObjectIdentifier.AUTHORITY_INFO_ACCESS;
import static de.rub.nds.tlsattacker.core.certificate.ExtensionObjectIdentifier.CERTIFICATE_AUTHORITY_ISSUER;
import static de.rub.nds.tlsattacker.core.certificate.ExtensionObjectIdentifier.OCSP;
import static de.rub.nds.tlsattacker.core.certificate.ExtensionObjectIdentifier.TLS_FEATURE;

import com.google.common.io.ByteStreams;
import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1EncapsulatingOctetString;
import de.rub.nds.asn1.model.Asn1Explicit;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1PrimitiveIa5String;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.Asn1Parser;
import de.rub.nds.asn1.translator.ParseOcspTypesContext;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import static de.rub.nds.tlsattacker.core.certificate.ExtensionObjectIdentifier.SIGNED_CERTIFICATE_TIMESTAMP_LIST;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.util.Asn1ToolInitializer;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x509.Certificate;

public class CertificateInformationExtractor {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Certificate certificate;
    private List<Asn1Encodable> x509ExtensionSequences;
    private Asn1Sequence authorityInfoAccessEntities;
    private Asn1Sequence tlsFeatureExtension;
    private Asn1Sequence precertificateSctListExtension;
    private Boolean mustStaple;
    private Boolean mustStaplev2;
    private String ocspServerUrl;
    private String certificateIssuerUrl;

    private static final int X509_EXTENSION_ASN1_EXPLICIT_OFFSET = 3;
    private static final int STATUS_REQUEST_TLS_EXTENSION_ID = 5;
    private static final int STATUS_REQUEST_V2_TLS_EXTENSION_ID = 17;

    public CertificateInformationExtractor(Certificate certificate) {
        this.certificate = certificate;

        // Init ASN.1 Tool
        Asn1ToolInitializer.initAsn1Tool();
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public BigInteger getSerialNumber() {
        return certificate.getSerialNumber().getValue();
    }

    public byte[] getIssuerNameHash() {
        try {
            byte[] encodedDistinguishedName = certificate.getIssuer().getEncoded();
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            return md.digest(encodedDistinguishedName);
        } catch (NoSuchAlgorithmException | IOException ex) {
            throw new RuntimeException(ex);
        }
    }

    public byte[] getIssuerKeyHash() {
        byte[] publicKey = certificate.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-1");
            return md.digest(publicKey);
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
    }

    public Boolean getMustStaple() {
        if (mustStaple == null) {
            mustStaple = parseMustStaple();
        }
        return mustStaple;
    }

    public Boolean getMustStaplev2() {
        if (mustStaplev2 == null) {
            mustStaplev2 = parseMustStaplev2();
        }
        return mustStaplev2;
    }

    public String getOcspServerUrl() {
        if (ocspServerUrl == null) {
            ocspServerUrl = parseOcspServerUrl();
        }

        return ocspServerUrl;
    }

    public String getCertificateIssuerUrl() {
        if (certificateIssuerUrl == null) {
            certificateIssuerUrl = parseCertificateIssuerUrl();
        }

        return certificateIssuerUrl;
    }

    public Asn1Sequence getPrecertificateSCTs() {
        if (precertificateSctListExtension == null) {
            extractPrecertificateSCTs();
        }
        return precertificateSctListExtension;
    }

    private void extractX509Extensions() {
        String ocspUrlResult = null;

        byte[] certAsn1;
        try {
            certAsn1 = certificate.getEncoded();
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }

        // Parse ASN.1 structure of the certificate
        Asn1Parser asn1Parser = new Asn1Parser(certAsn1, false);
        List<Asn1Encodable> asn1Encodables = asn1Parser.parse(ParseOcspTypesContext.NAME);

        /*
         * Navigate through the mess to the OCSP URL. First, just unroll the two outer ASN.1 sequences to get to most of
         * the information stored in a X.509 certificate.
         */
        Asn1Sequence innerObjects = (Asn1Sequence) ((Asn1Sequence) asn1Encodables.get(0)).getChildren().get(0);

        // Get sequence containing X.509 extensions
        Asn1Explicit x509Extensions = null;

        for (Asn1Encodable singleObject : innerObjects.getChildren()) {
            if (singleObject instanceof Asn1Explicit) {
                if (((Asn1Explicit) singleObject).getOffset() == X509_EXTENSION_ASN1_EXPLICIT_OFFSET) {
                    x509Extensions = (Asn1Explicit) singleObject;
                    break;
                }
            }
        }
        if (x509Extensions != null && !x509Extensions.getChildren().isEmpty()) {
            x509ExtensionSequences = ((Asn1Sequence) x509Extensions.getChildren().get(0)).getChildren();
        }
    }

    /**
     *
     * @throws CertificateException
     *                              If the AuthorityInfoAccessEntities are not present in the certificate.
     */
    private void extractAuthorityInfoAccessEntities() throws CertificateException {
        // Now that we found the extensions, search for the
        // 'authorityInfoAccess' extension
        Asn1Sequence authorityInfoAccess = null;

        for (Asn1Encodable singleExtension : x509ExtensionSequences) {
            if (singleExtension instanceof Asn1Sequence) {
                Asn1ObjectIdentifier objectIdentifier =
                    (Asn1ObjectIdentifier) (((Asn1Sequence) singleExtension).getChildren().get(0));
                // This is the objectIdentifier value for
                // authorityInfoAccess
                if (objectIdentifier.getValue().equals(AUTHORITY_INFO_ACCESS.getOID())) {
                    authorityInfoAccess = (Asn1Sequence) singleExtension;
                    break;
                }
            }
        }

        if (authorityInfoAccess == null) {
            throw new CertificateException("No 'Authority Info Access' entry found in certificate.");
        }
        /*
         * get(0) is the Object Identifier we checked, get(1) the Octet String with the content the Octet String has a
         * sequence as child, and one of them has the desired OCSP information. Almost there!
         */
        Asn1EncapsulatingOctetString authorityInfoAccessContent =
            (Asn1EncapsulatingOctetString) authorityInfoAccess.getChildren().get(1);

        this.authorityInfoAccessEntities = (Asn1Sequence) authorityInfoAccessContent.getChildren().get(0);
    }

    private void extractTlsFeatureExtension() {
        if (x509ExtensionSequences == null) {
            extractX509Extensions();
        }

        // Search for X.509 'TLS Feature' extension
        for (Asn1Encodable enc : x509ExtensionSequences) {
            if (enc instanceof Asn1Sequence) {
                Asn1ObjectIdentifier objectIdentifier =
                    (Asn1ObjectIdentifier) (((Asn1Sequence) enc).getChildren().get(0));
                // This is the objectIdentifier value for RFC 7633, which
                // defines the TLS feature X.509 extension
                if (objectIdentifier.getValue().equals(TLS_FEATURE.getOID())) {
                    tlsFeatureExtension = (Asn1Sequence) enc;
                    break;
                }
            }
        }
    }

    private void extractPrecertificateSCTs() {
        if (x509ExtensionSequences == null) {
            extractX509Extensions();
        }

        // Search for X.509 'Signed Certificate Timestamp List' extension
        for (Asn1Encodable enc : x509ExtensionSequences) {
            if (enc instanceof Asn1Sequence) {
                Asn1ObjectIdentifier objectIdentifier =
                    (Asn1ObjectIdentifier) (((Asn1Sequence) enc).getChildren().get(0));

                if (objectIdentifier.getValue().equals(SIGNED_CERTIFICATE_TIMESTAMP_LIST.getOID())) {
                    precertificateSctListExtension = (Asn1Sequence) enc;
                    break;
                }
            }
        }
    }

    private boolean parseMustStaple() {
        if (tlsFeatureExtension == null) {
            extractTlsFeatureExtension();
        }

        boolean foundMustStaple = false;

        // Search value inside 'TLS Feature' extension to search for
        // 'status_request'
        if (tlsFeatureExtension != null) {
            Asn1EncapsulatingOctetString tlsFeaturesContent =
                (Asn1EncapsulatingOctetString) tlsFeatureExtension.getChildren().get(1);
            Asn1Sequence tlsFeaturesContentSequence = (Asn1Sequence) tlsFeaturesContent.getChildren().get(0);

            for (Asn1Encodable feature : tlsFeaturesContentSequence.getChildren()) {
                if (feature instanceof Asn1Integer) {
                    if (((Asn1Integer) feature).getValue().intValue() == STATUS_REQUEST_TLS_EXTENSION_ID) {
                        foundMustStaple = true;
                    }
                }
            }
        }

        return foundMustStaple;
    }

    private boolean parseMustStaplev2() {
        if (tlsFeatureExtension == null) {
            extractTlsFeatureExtension();
        }

        boolean foundMustStaplev2 = false;

        // Search value inside 'TLS Feature' extension to search for
        // 'status_request_v2'
        if (tlsFeatureExtension != null) {
            Asn1EncapsulatingOctetString tlsFeaturesContent =
                (Asn1EncapsulatingOctetString) tlsFeatureExtension.getChildren().get(1);
            Asn1Sequence tlsFeaturesContentSequence = (Asn1Sequence) tlsFeaturesContent.getChildren().get(0);

            for (Asn1Encodable feature : tlsFeaturesContentSequence.getChildren()) {
                if (feature instanceof Asn1Integer) {
                    if (((Asn1Integer) feature).getValue().intValue() == STATUS_REQUEST_V2_TLS_EXTENSION_ID) {
                        foundMustStaplev2 = true;
                    }
                }
            }
        }

        return foundMustStaplev2;
    }

    private String getStringFromInformationAccessEntry(List<Asn1Encodable> authorityInformationAccessInformation) {
        String urlString = null;
        if (authorityInformationAccessInformation != null) {
            Asn1PrimitiveIa5String urlIa5String = null;
            if (authorityInformationAccessInformation.size() > 1
                && authorityInformationAccessInformation.get(1) instanceof Asn1PrimitiveIa5String) {
                urlIa5String = (Asn1PrimitiveIa5String) authorityInformationAccessInformation.get(1);
            }
            urlString = urlIa5String.getValue();
        }

        return urlString;
    }

    private String parseOcspServerUrl() {
        if (x509ExtensionSequences == null) {
            extractX509Extensions();
            if (x509ExtensionSequences == null) {
                return null;
            }
        }
        if (authorityInfoAccessEntities == null) {
            try {
                extractAuthorityInfoAccessEntities();
            } catch (CertificateException e) {
                LOGGER.debug(e.getMessage());
                return null;
            }
        }

        List<Asn1Encodable> ocspInformation = null;

        // Now let's check if we have OCSP information embedded...
        for (Asn1Encodable enc : authorityInfoAccessEntities.getChildren()) {
            if (enc instanceof Asn1Sequence) {
                Asn1ObjectIdentifier objectIdentifier =
                    (Asn1ObjectIdentifier) ((Asn1Sequence) enc).getChildren().get(0);
                // This is the objectIdentifier value for OCSP
                if (objectIdentifier.getValue().equals(OCSP.getOID())) {
                    ocspInformation = ((Asn1Sequence) enc).getChildren();
                    break;
                }
            }
        }

        if (ocspInformation == null) {
            LOGGER.debug("No OCSP entry found in certificate.");
            return null;
        }

        // If we found the OCSP information, let's extract it and we're
        // done!
        return getStringFromInformationAccessEntry(ocspInformation);
    }

    private String parseCertificateIssuerUrl() {
        if (x509ExtensionSequences == null) {
            extractX509Extensions();
        }
        if (authorityInfoAccessEntities == null) {
            try {
                extractAuthorityInfoAccessEntities();
            } catch (CertificateException e) {
                LOGGER.debug(e.getMessage());
                return null;
            }
        }

        List<Asn1Encodable> certificateIssuerInformation = null;

        // Now let's check if we have OCSP information embedded...
        for (Asn1Encodable enc : authorityInfoAccessEntities.getChildren()) {
            if (enc instanceof Asn1Sequence) {
                Asn1ObjectIdentifier objectIdentifier =
                    (Asn1ObjectIdentifier) ((Asn1Sequence) enc).getChildren().get(0);
                // This is the objectIdentifier value for OCSP
                if (objectIdentifier.getValue().equals(CERTIFICATE_AUTHORITY_ISSUER.getOID())) {
                    certificateIssuerInformation = ((Asn1Sequence) enc).getChildren();
                    break;
                }
            }
        }

        if (certificateIssuerInformation == null) {
            LOGGER.debug("No Certificate Issuer entry found in certificate.");
            return null;
        }

        // If we found the OCSP information, let's extract it and we're
        // done!
        return getStringFromInformationAccessEntry(certificateIssuerInformation);
    }

    public Certificate retrieveIssuerCertificate() {
        /*
         * Certificate chain recreation sucks. We only support .crt / DER-encoded certificates for extraction, as this
         * seems to be the most common one out there and is somewhat easy to parse with BouncyCastle. This only works
         * somewhat reliably with an intermediate CA as issuer. Any root CA will likely fail, as an URL to the issuer
         * certificate is often not given in the intermediate's certificate (since they're often stored locally). So
         * take care, the following code will likely fail often.
         */

        // Get URL for the issuer certificate from main certificate
        String issuerCertificateUrlString = getCertificateIssuerUrl();
        URL issuerCertificateUrl;
        try {
            if (issuerCertificateUrlString != null) {

                issuerCertificateUrl = new URL(issuerCertificateUrlString);

            } else {
                LOGGER.debug("Didn't get any issuer certificate URL from certificate.");
                return null;
            }

            // Download certificate from URL
            HttpURLConnection httpCon = (HttpURLConnection) issuerCertificateUrl.openConnection();
            httpCon.setConnectTimeout(5000);
            httpCon.setRequestMethod("GET");

            int status = httpCon.getResponseCode();
            byte[] response;
            if (status == 200) {
                response = ByteStreams.toByteArray(httpCon.getInputStream());
            } else {
                LOGGER.debug("Response not successful: Received status code " + status);
                httpCon.disconnect();
                return null;
            }

            httpCon.disconnect();

            // Recreate TLS certificate length information
            byte[] certificateWithLength = ArrayConverter.concatenate(
                ArrayConverter.intToBytes(response.length, HandshakeByteLength.CERTIFICATES_LENGTH), response);
            ByteArrayInputStream stream = new ByteArrayInputStream(ArrayConverter.concatenate(
                ArrayConverter.intToBytes(certificateWithLength.length, HandshakeByteLength.CERTIFICATES_LENGTH),
                certificateWithLength));

            // Parse and create a Certificate object
            org.bouncycastle.crypto.tls.Certificate tlsCertificate =
                org.bouncycastle.crypto.tls.Certificate.parse(stream);
            return tlsCertificate.getCertificateAt(0);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }
}
