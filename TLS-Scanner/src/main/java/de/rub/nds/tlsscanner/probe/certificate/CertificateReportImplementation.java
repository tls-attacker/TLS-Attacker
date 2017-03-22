/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.probe.certificate;

import de.rub.nds.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import java.security.PublicKey;
import java.util.Date;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
class CertificateReportImplementation implements CertificateReport {

    private String subject;
    private String commonNames;
    private String alternativenames;
    private Date validFrom;
    private Date validTo;
    private PublicKey publicKey;
    private Boolean weakDebianKey;
    private String issuer;
    private SignatureAndHashAlgorithm signatureAndHashAlgorithm;
    private Boolean extendedValidation;
    private Boolean certificateTransparency;
    private Boolean ocspMustStaple;
    private Boolean crlSupported;
    private Boolean ocspSupported;
    private Boolean revoked;
    private Boolean dnsCAA;
    private Boolean trusted;

    public CertificateReportImplementation() {
    }

    @Override
    public String getSubject() {
        return subject;
    }

    @Override
    public String getCommonNames() {
        return commonNames;
    }

    @Override
    public String getAlternativenames() {
        return alternativenames;
    }

    @Override
    public Date getValidFrom() {
        return validFrom;
    }

    @Override
    public Date getValidTo() {
        return validTo;
    }

    @Override
    public PublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public Boolean getWeakDebianKey() {
        return weakDebianKey;
    }

    @Override
    public String getIssuer() {
        return issuer;
    }

    @Override
    public SignatureAndHashAlgorithm getSignatureAndHashAlgorithm() {
        return signatureAndHashAlgorithm;
    }

    @Override
    public Boolean getExtendedValidation() {
        return extendedValidation;
    }

    @Override
    public Boolean getCertificateTransparency() {
        return certificateTransparency;
    }

    @Override
    public Boolean getOcspMustStaple() {
        return ocspMustStaple;
    }

    @Override
    public Boolean getCrlSupported() {
        return crlSupported;
    }

    @Override
    public Boolean getOcspSupported() {
        return ocspSupported;
    }

    @Override
    public Boolean getRevoked() {
        return revoked;
    }

    @Override
    public Boolean getDnsCAA() {
        return dnsCAA;
    }

    public Boolean getTrusted() {
        return trusted;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public void setCommonNames(String commonNames) {
        this.commonNames = commonNames;
    }

    public void setAlternativenames(String alternativenames) {
        this.alternativenames = alternativenames;
    }

    public void setValidFrom(Date validFrom) {
        this.validFrom = validFrom;
    }

    public void setValidTo(Date validTo) {
        this.validTo = validTo;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public void setWeakDebianKey(Boolean weakDebianKey) {
        this.weakDebianKey = weakDebianKey;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public void setSignatureAndHashAlgorithm(SignatureAndHashAlgorithm signatureAndHashAlgorithm) {
        this.signatureAndHashAlgorithm = signatureAndHashAlgorithm;
    }

    public void setExtendedValidation(Boolean extendedValidation) {
        this.extendedValidation = extendedValidation;
    }

    public void setCertificateTransparency(Boolean certificateTransparency) {
        this.certificateTransparency = certificateTransparency;
    }

    public void setOcspMustStaple(Boolean ocspMustStaple) {
        this.ocspMustStaple = ocspMustStaple;
    }

    public void setCrlSupported(Boolean crlSupported) {
        this.crlSupported = crlSupported;
    }

    public void setOcspSupported(Boolean ocspSupported) {
        this.ocspSupported = ocspSupported;
    }

    public void setRevoked(Boolean revoked) {
        this.revoked = revoked;
    }

    public void setDnsCAA(Boolean dnsCAA) {
        this.dnsCAA = dnsCAA;
    }

    public void setTrusted(Boolean trusted) {
        this.trusted = trusted;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        if (subject != null) {
            builder.append("Subject: ").append(subject).append("\n");
        }
        if (commonNames != null) {
            builder.append("CommonNames: ").append(commonNames).append("\n");
        }
        if (alternativenames != null) {
            builder.append("AltNames: ").append(alternativenames).append("\n");
        }
        if (validFrom != null) {
            builder.append("Valid From: ").append(validFrom.toString()).append("\n");
        }
        if (validTo != null) {
            builder.append("Valid Till: ").append(validTo.toString()).append("\n");
        }
        if (publicKey != null) {
            builder.append("PublicKey: ").append(publicKey.toString()).append("\n");
        }
        if (weakDebianKey != null) {
            builder.append("Weak Debian Key: ").append(weakDebianKey).append("\n");
        }
        if (issuer != null) {
            builder.append("Issuer: ").append(issuer).append("\n");
        }
        if (signatureAndHashAlgorithm != null) {
            builder.append("Signature Algorithm: ").append(signatureAndHashAlgorithm.getSignatureAlgorithm().name())
                    .append("\n");
        }
        if (signatureAndHashAlgorithm != null) {
            builder.append("Hash Algorithm: ").append(signatureAndHashAlgorithm.getHashAlgorithm().name()).append("\n");
        }
        if (extendedValidation != null) {
            builder.append("Extended Validation: ").append(extendedValidation).append("\n");
        }
        if (certificateTransparency != null) {
            builder.append("Certificate Transparency: ").append(certificateTransparency).append("\n");
        }
        if (ocspMustStaple != null) {
            builder.append("OCSP must Staple: ").append(ocspMustStaple).append("\n");
        }
        if (crlSupported != null) {
            builder.append("CRL Supported: ").append(crlSupported).append("\n");
        }
        if (ocspSupported != null) {
            builder.append("OCSP Supported: ").append(ocspSupported).append("\n");
        }
        if (revoked != null) {
            builder.append("Is Revoked: ").append(revoked).append("\n");
        }
        if (dnsCAA != null) {
            builder.append("DNS CCA: ").append(dnsCAA).append("\n");
        }
        if (trusted != null) {
            builder.append("Trusted: ").append(trusted).append("\n");
        }
        return builder.toString();
    }

}
