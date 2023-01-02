/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.crypto.keys.*;
import de.rub.nds.tlsattacker.core.util.CertificateUtils;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.x509attacker.x509.base.X509CertificateChain;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElements;
import java.io.*;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlAccessorType(XmlAccessType.FIELD)
public class CertificateKeyPair implements Serializable {

    private static final Logger LOGGER = LogManager.getLogger();

    private X509CertificateChain x509CertificateChain;

    @XmlElements(
            value = {
                @XmlElement(type = CustomDhPublicKey.class, name = "DhPublicKey"),
                @XmlElement(type = CustomDsaPublicKey.class, name = "DsaPublicKey"),
                @XmlElement(type = CustomRsaPublicKey.class, name = "RsaPublicKey"),
                @XmlElement(type = CustomEcPublicKey.class, name = "EcPublicKey")
            })
    private final CustomPublicKey publicKey;

    @XmlElements(
            value = {
                @XmlElement(type = CustomDHPrivateKey.class, name = "DhPrivateKey"),
                @XmlElement(type = CustomDSAPrivateKey.class, name = "DsaPrivateKey"),
                @XmlElement(type = CustomRSAPrivateKey.class, name = "RsaPrivateKey"),
                @XmlElement(type = CustomECPrivateKey.class, name = "EcPrivateKey")
            })
    private final CustomPrivateKey privateKey;

    private CertificateKeyPair() {
        this.x509CertificateChain = null;
        this.publicKey = null;
        this.privateKey = null;
    }

    public CertificateKeyPair(
            X509CertificateChain x509CertificateChain,
            CustomPublicKey publicKey,
            CustomPrivateKey privateKey) {
        this.x509CertificateChain = x509CertificateChain;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public CertificateKeyPair(
            X509CertificateChain x509CertificateChain,
            CustomPrivateKey privateKey) {
        this.x509CertificateChain = x509CertificateChain;
        
        this.privateKey = privateKey;
        throw new UnsupportedOperationException("public key not set - implement");
    }

    public CertificateKeyPair(X509CertificateChain x509CertificateChain, PrivateKey privateKey, PublicKey publicKey) {
        this.x509CertificateChain = x509CertificateChain;
        this.privateKey = CertificateUtils.parseCustomPrivateKey(privateKey);
        this.publicKey = CertificateUtils.parseCustomPublicKey(publicKey);
    }

    public CustomPublicKey getPublicKey() {
        return publicKey;
    }

    public CustomPrivateKey getPrivateKey() {
        return privateKey;
    }

    public CertificateKeyType getLeafCertificateKeyType() {
        return CertificateAnalyzer.getCertificateKeyType(x509CertificateChain.getLeaf());
    }
    
    public NamedGroup getLeafPublicKeyNamedGroup() {
        return CertificateAnalyzer.getPublicNamedGroup(x509CertificateChain.getLeaf());
    }
    
    public NamedGroup getLeafSignatureNamedGroup() {
        return CertificateAnalyzer.getSignatureNamedGroup(x509CertificateChain.getLeaf());
    }

    public X509CertificateChain getX509CertificateChain() {
        return x509CertificateChain;
    }

    public void adjustInConfig(Config config, ConnectionEndType connectionEnd) {
        publicKey.adjustInConfig(config, connectionEnd);
        if (privateKey != null) {
            privateKey.adjustInConfig(config, connectionEnd);
        }
        config.setDefaultExplicitCertificateKeyPair(this);
    }


    @Override
    public int hashCode() {
        int hash = 3;
        hash = 29 * hash + Objects.hashCode(this.x509CertificateChain);
        hash = 29 * hash + Objects.hashCode(this.publicKey);
        hash = 29 * hash + Objects.hashCode(this.privateKey);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final CertificateKeyPair other = (CertificateKeyPair) obj;

        if (!Objects.equals(this.x509CertificateChain, other.x509CertificateChain)) {
            return false;
        }
        if (!Objects.equals(this.publicKey, other.publicKey)) {
            return false;
        }
        return Objects.equals(this.privateKey, other.privateKey);
    }

    @Override
    public String toString() {
        return "CertificateKeyPair{" + "x509CertificateChain=" + x509CertificateChain + ", publicKey=" + publicKey + ", privateKey=" + privateKey + '}';
    }

    public boolean isCompatibleWithCipherSuite(Chooser chooser) {
        CipherSuite cipherSuite = chooser.getSelectedCipherSuite();
        if (!cipherSuite.isRealCipherSuite()
                || (cipherSuite.isTLS13() && !combinationUnsuitedForTls13(chooser))) {
            return true;
        } else if (cipherSuite.isTLS13() && combinationUnsuitedForTls13(chooser)) {
            return false;
        }

        CertificateKeyType neededKeyType = AlgorithmResolver.getCertificateKeyType(cipherSuite);
        CertificateKeyType legacyNeededCertSignatureKeyType
                = AlgorithmResolver.getRequiredSignatureAlgorithm(cipherSuite)
                        .getRequiredCertificateKeyType();

        if (neededKeyType == CertificateAnalyzer.getCertificateKeyType(x509CertificateChain.getLeaf())
                || (neededKeyType == CertificateKeyType.ECDH_ECDSA
                && CertificateAnalyzer.getCertificateKeyType(x509CertificateChain.getLeaf()) == CertificateKeyType.ECDH)) {
            if (cipherSuite.isEphemeral()
                    || mayUseArbitraryCertSignature(chooser)
                    || legacyNeededCertSignatureKeyType == CertificateAnalyzer.getCertificateKeyType(x509CertificateChain.getLeaf())) {
                return true;
            }
        }
        return false;
    }

    private boolean mayUseArbitraryCertSignature(Chooser chooser) {
        ProtocolVersion selectedVersion = chooser.getSelectedProtocolVersion();
        return (selectedVersion != ProtocolVersion.SSL3
                && selectedVersion != ProtocolVersion.TLS10
                && selectedVersion != ProtocolVersion.TLS11
                && selectedVersion != ProtocolVersion.DTLS10);
    }

    public boolean combinationUnsuitedForTls13(Chooser chooser) {
        return SignatureAndHashAlgorithm.forCertificateKeyPair(this, chooser, true) == null
                || !SignatureAndHashAlgorithm.forCertificateKeyPair(this, chooser, true)
                        .suitedForSigningTls13Messages();
    }

    public SignatureAndHashAlgorithm getLeafSignatureAndHashAlgorithm() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
