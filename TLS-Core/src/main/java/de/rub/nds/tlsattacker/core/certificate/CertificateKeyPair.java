/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.certificate;

import de.rub.nds.modifiablevariable.util.ByteArrayAdapter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CertificateKeyType;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomDHPrivateKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomDSAPrivateKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomDhPublicKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomDsaPublicKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomECPrivateKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomEcPublicKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomPrivateKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomPublicKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomRSAPrivateKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.util.CertificateUtils;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Objects;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

@XmlAccessorType(XmlAccessType.FIELD)
public class CertificateKeyPair implements Serializable {

    protected static final Logger LOGGER = LogManager.getLogger(CertificateKeyPair.class.getName());

    private final CertificateKeyType certPublicKeyType;

    private final CertificateKeyType certSignatureType;

    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private final byte[] certificateBytes;

    @XmlElements(value = { @XmlElement(type = CustomDhPublicKey.class, name = "DhPublicKey"),
            @XmlElement(type = CustomDsaPublicKey.class, name = "DsaPublicKey"),
            @XmlElement(type = CustomRsaPublicKey.class, name = "RsaPublicKey"),
            @XmlElement(type = CustomEcPublicKey.class, name = "EcPublicKey") })
    private final CustomPublicKey publicKey;

    @XmlElements(value = { @XmlElement(type = CustomDHPrivateKey.class, name = "DhPrivateKey"),
            @XmlElement(type = CustomDSAPrivateKey.class, name = "DsaPrivateKey"),
            @XmlElement(type = CustomRSAPrivateKey.class, name = "RsaPrivateKey"),
            @XmlElement(type = CustomECPrivateKey.class, name = "EcPrivateKey") })
    private final CustomPrivateKey privateKey;

    private final NamedGroup signatureGroup;

    private final NamedGroup publicKeyGroup;

    private CertificateKeyPair() {
        this.certPublicKeyType = null;
        this.certSignatureType = null;
        this.certificateBytes = null;
        this.publicKey = null;
        this.privateKey = null;
        this.signatureGroup = null;
        this.publicKeyGroup = null;
    }

    public CertificateKeyPair(CertificateKeyType certPublicKeyType, CertificateKeyType certSignatureType,
            byte[] certificateBytes, CustomPublicKey publicKey, CustomPrivateKey privateKey, NamedGroup signatureGroup,
            NamedGroup publicKeyGroup) {
        this.certPublicKeyType = certPublicKeyType;
        this.certSignatureType = certSignatureType;
        this.certificateBytes = certificateBytes;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.signatureGroup = signatureGroup;
        this.publicKeyGroup = publicKeyGroup;
    }

    public CertificateKeyPair(Certificate cert, PrivateKey key) throws IOException {
        this.certPublicKeyType = getPublicKeyType(cert);
        this.certSignatureType = getSignatureType(cert);
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        cert.encode(stream);
        this.certificateBytes = stream.toByteArray();
        this.privateKey = CertificateUtils.parseCustomPrivateKey(key);
        this.publicKey = CertificateUtils.parseCustomPublicKey(CertificateUtils.parsePublicKey(cert));
        this.publicKeyGroup = getPublicNamedGroup(cert);
        this.signatureGroup = getSignatureNamedGroup(cert);
    }

    private CertificateKeyType getPublicKeyType(Certificate cert) {
        if (cert.isEmpty()) {
            throw new IllegalArgumentException("Empty CertChain provided!");
        }
        AlgorithmIdentifier algorithm = cert.getCertificateAt(0).getSubjectPublicKeyInfo().getAlgorithm();
        switch (algorithm.getAlgorithm().getId()) {
            case "1.2.840.113549.1.1.1":
                return CertificateKeyType.RSA;
            case "1.2.840.10045.2.1":
                return CertificateKeyType.ECDSA;
            case "1.2.840.113549.1.3.1":
                return CertificateKeyType.DH;
            case "1.2.840.10040.4.1":
                return CertificateKeyType.DSS;
            default:
                LOGGER.warn("Unknown algorithm ID: " + algorithm.getAlgorithm().getId() + " using \"NONE\"");
                System.out.println("pk:" + algorithm.getAlgorithm().toString());
                return CertificateKeyType.NONE;
        }
    }

    private CertificateKeyType getSignatureType(Certificate cert) {
        if (cert.isEmpty()) {
            throw new IllegalArgumentException("Empty CertChain provided!");
        }
        AlgorithmIdentifier algorithm = cert.getCertificateAt(0).getSignatureAlgorithm();
        switch (algorithm.getAlgorithm().getId()) {
            case "1.2.840.113549.1.1.11":
                return CertificateKeyType.RSA;
            case "1.2.840.10045.4.3.2":
                return CertificateKeyType.ECDSA;
            case "2.16.840.1.101.3.4.3.2":
                return CertificateKeyType.DSS;
            default:
                System.out.println("sig:" + algorithm.getAlgorithm().toString());
                LOGGER.warn("Unknown algorithm ID: " + algorithm.getAlgorithm().getId() + " using \"NONE\"");
                return CertificateKeyType.NONE;
        }
    }

    private NamedGroup getSignatureNamedGroup(Certificate cert) {
        if (cert.isEmpty()) {
            throw new IllegalArgumentException("Empty CertChain provided!");
        }
        if (!(publicKey instanceof CustomEcPublicKey)) {
            return null;
        }
        // TODO Okay - we currently do not support mixed group ecdsa
        // pubKey/signature certficiates
        // i am not sure if they are actually allowed to exist- we assume that
        // the signature group is
        // the same as for the public key
        try {
            X509CertificateObject obj = new X509CertificateObject(cert.getCertificateAt(0));
            BCECPublicKey ecKey = (BCECPublicKey) obj.getPublicKey();
            ECNamedCurveSpec spec = (ECNamedCurveSpec) ecKey.getParams();
            NamedGroup group = NamedGroup.fromJavaName(spec.getName());
            if (group == null) {
                return null;
            } else {
                return group;
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            LOGGER.warn("Could not determine EC public key group", ex);
            return null;
        }
    }

    private NamedGroup getPublicNamedGroup(Certificate cert) {
        if (cert.isEmpty()) {
            throw new IllegalArgumentException("Empty CertChain provided!");
        }
        if (!(publicKey instanceof CustomEcPublicKey)) {
            return null;
        }
        try {
            X509CertificateObject obj = new X509CertificateObject(cert.getCertificateAt(0));
            BCECPublicKey ecKey = (BCECPublicKey) obj.getPublicKey();
            ECNamedCurveSpec spec = (ECNamedCurveSpec) ecKey.getParams();
            return NamedGroup.fromJavaName(spec.getName());
        } catch (Exception ex) {
            LOGGER.warn("Could not determine EC public key group", ex);
            return null;
        }
    }

    public CertificateKeyPair(CertificateKeyType certPublicKeyType, CertificateKeyType certSignatureType,
            File certFile, File privateKeyFile) throws CertificateException, IOException {
        this.certPublicKeyType = certPublicKeyType;
        this.certSignatureType = certSignatureType;
        Certificate certificate = PemUtil.readCertificate(certFile);
        this.publicKey = CertificateUtils.parseCustomPublicKey(PemUtil.readPublicKey(certFile));
        this.privateKey = CertificateUtils.parseCustomPrivateKey(PemUtil.readPrivateKey(privateKeyFile));
        certificateBytes = certificate.getCertificateAt(0).getEncoded();
        certSignatureType = null;
        certPublicKeyType = null;
        signatureGroup = null;
        publicKeyGroup = null; // TODO
    }

    public CertificateKeyType getCertPublicKeyType() {
        return certPublicKeyType;
    }

    public CertificateKeyType getCertSignatureType() {
        return certSignatureType;
    }

    public byte[] getCertificateBytes() {
        return certificateBytes;
    }

    public CustomPublicKey getPublicKey() {
        return publicKey;
    }

    public CustomPrivateKey getPrivateKey() {
        return privateKey;
    }

    public NamedGroup getSignatureGroup() {
        return signatureGroup;
    }

    public NamedGroup getPublicKeyGroup() {
        return publicKeyGroup;
    }

    public void adjustInConfig(Config config, ConnectionEndType connectionEnd) {
        publicKey.adjustInConfig(config, connectionEnd);
        privateKey.adjustInConfig(config, connectionEnd);
        config.setDefaultExplicitCertificateKeyPair(this);
    }

    public void adjustInContext(TlsContext context, ConnectionEndType connectionEnd) {
        publicKey.adjustInContext(context, connectionEnd);
        privateKey.adjustInContext(context, connectionEnd);
        System.out.println(privateKey);
        context.setSelectedGroup(publicKeyGroup);
        if (context.getConfig().getAutoAdjustSignatureAndHashAlgorithm()) {
            // TODO rething auto selection
            SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RSA;
            switch (certPublicKeyType) {
                case ECDSA:
                    signatureAlgorithm = SignatureAlgorithm.ECDSA;
                    break;
                case RSA:
                    signatureAlgorithm = SignatureAlgorithm.RSA;
                    break;
                case DSS:
                    signatureAlgorithm = SignatureAlgorithm.DSA;
                    break;
            }
            context.setSelectedSignatureAndHashAlgorithm(SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(
                    signatureAlgorithm, context.getConfig().getPreferredHashAlgorithm()));
        }
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 29 * hash + Objects.hashCode(this.certPublicKeyType);
        hash = 29 * hash + Objects.hashCode(this.certSignatureType);
        hash = 29 * hash + Arrays.hashCode(this.certificateBytes);
        hash = 29 * hash + Objects.hashCode(this.publicKey);
        hash = 29 * hash + Objects.hashCode(this.privateKey);
        hash = 29 * hash + Objects.hashCode(this.signatureGroup);
        hash = 29 * hash + Objects.hashCode(this.publicKeyGroup);
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
        if (this.certPublicKeyType != other.certPublicKeyType) {
            return false;
        }
        if (this.certSignatureType != other.certSignatureType) {
            return false;
        }
        if (!Arrays.equals(this.certificateBytes, other.certificateBytes)) {
            return false;
        }
        if (!Objects.equals(this.publicKey, other.publicKey)) {
            return false;
        }
        if (!Objects.equals(this.privateKey, other.privateKey)) {
            return false;
        }
        if (this.signatureGroup != other.signatureGroup) {
            return false;
        }
        if (this.publicKeyGroup != other.publicKeyGroup) {
            return false;
        }
        return true;
    }

    public boolean isCertificateParseable() {
        try {
            Certificate cert = Certificate.parse(new ByteArrayInputStream(certificateBytes));
            return true;
        } catch (Exception E) {
            return false;
        }
    }
}
