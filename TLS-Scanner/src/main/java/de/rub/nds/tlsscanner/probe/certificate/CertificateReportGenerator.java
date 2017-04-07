/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe.certificate;

import de.rub.nds.tlsattacker.tls.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.jce.provider.X509CertificateObject;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateReportGenerator {

    private static final Logger LOGGER = LogManager.getLogger("Probe");

    public static List<CertificateReport> generateReports(Certificate certs) {
        List<CertificateReport> reportList = new LinkedList<>();
        reportList.add(generateReport(certs.getCertificateAt(0)));

        return reportList;
    }

    public static CertificateReport generateReport(org.bouncycastle.asn1.x509.Certificate cert) {
        CertificateReportImplementation report = new CertificateReportImplementation();
        setSubject(report, cert);
        setCommonNames(report, cert);
        setAlternativeNames(report, cert);
        setValidFrom(report, cert);
        setValidTo(report, cert);
        setPubkey(report, cert);
        setWeakDebianKey(report, cert);
        setIssuer(report, cert);
        setSignatureAndHashAlgorithm(report, cert);
        setExtendedValidation(report, cert);
        setCeritifcateTransparency(report, cert);
        setOcspMustStaple(report, cert);
        setCRLSupported(report, cert);
        setOcspSupported(report, cert);
        setRevoked(report, cert);
        setDnsCCA(report, cert);
        setTrusted(report, cert);
        return report;
    }

    private static void setSubject(CertificateReportImplementation report, org.bouncycastle.asn1.x509.Certificate cert) {
        X500Name x500name = cert.getSubject();
        RDN cn = x500name.getRDNs(BCStyle.CN)[0];
        report.setCommonNames(IETFUtils.valueToString(cn.getFirst().getValue()));
    }

    private static void setCommonNames(CertificateReportImplementation report,
            org.bouncycastle.asn1.x509.Certificate cert) {
        X500Name x500name = cert.getSubject();
        RDN cn = x500name.getRDNs(BCStyle.CN)[0];
        report.setCommonNames(IETFUtils.valueToString(cn.getFirst().getValue()));
    }

    private static void setAlternativeNames(CertificateReportImplementation report,
            org.bouncycastle.asn1.x509.Certificate cert) {

    }

    private static void setValidFrom(CertificateReportImplementation report, org.bouncycastle.asn1.x509.Certificate cert) {
        report.setValidFrom(cert.getStartDate().getDate());
    }

    private static void setValidTo(CertificateReportImplementation report, org.bouncycastle.asn1.x509.Certificate cert) {
        report.setValidTo(cert.getEndDate().getDate());
    }

    private static void setPubkey(CertificateReportImplementation report, org.bouncycastle.asn1.x509.Certificate cert) {
        try {
            X509Certificate x509Cert = new X509CertificateObject(cert);
            report.setPublicKey(x509Cert.getPublicKey());
        } catch (CertificateParsingException ex) {
            // TODO log could not set public key
        }
    }

    private static void setWeakDebianKey(CertificateReportImplementation report,
            org.bouncycastle.asn1.x509.Certificate cert) {
    }

    private static void setIssuer(CertificateReportImplementation report, org.bouncycastle.asn1.x509.Certificate cert) {
        report.setIssuer(cert.getIssuer().toString());
    }

    private static void setSignatureAndHashAlgorithm(CertificateReportImplementation report,
            org.bouncycastle.asn1.x509.Certificate cert) {
        String sigAndHashString = null;
        try {
            X509CertificateObject x509Cert = new X509CertificateObject(cert);
            sigAndHashString = x509Cert.getSigAlgName();
            System.out.println(sigAndHashString);
            String[] algos = sigAndHashString.toUpperCase().split("WITH");
            if (algos.length != 2) {
                return;
            }
            SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.valueOf(algos[1]);
            HashAlgorithm hashAlgorithm = HashAlgorithm.valueOf(algos[0]);
            if (hashAlgorithm == null || signatureAlgorithm == null) {
                return;
            }
            SignatureAndHashAlgorithm sigHashAlgo = new SignatureAndHashAlgorithm(signatureAlgorithm, hashAlgorithm);
            report.setSignatureAndHashAlgorithm(sigHashAlgo);
        } catch (Exception E) {
            LOGGER.debug("Could not extraxt SignatureAndHashAlgorithm from String:" + sigAndHashString, E);
        }
    }

    private static void setExtendedValidation(CertificateReportImplementation report,
            org.bouncycastle.asn1.x509.Certificate cert) {

    }

    private static void setCeritifcateTransparency(CertificateReportImplementation report,
            org.bouncycastle.asn1.x509.Certificate cert) {
    }

    private static void setOcspMustStaple(CertificateReportImplementation report,
            org.bouncycastle.asn1.x509.Certificate cert) {
    }

    private static void setCRLSupported(CertificateReportImplementation report,
            org.bouncycastle.asn1.x509.Certificate cert) {
    }

    private static void setOcspSupported(CertificateReportImplementation report,
            org.bouncycastle.asn1.x509.Certificate cert) {
    }

    private static void setRevoked(CertificateReportImplementation report, org.bouncycastle.asn1.x509.Certificate cert) {
    }

    private static void setDnsCCA(CertificateReportImplementation report, org.bouncycastle.asn1.x509.Certificate cert) {
    }

    private static void setTrusted(CertificateReportImplementation report, org.bouncycastle.asn1.x509.Certificate cert) {
    }
}
