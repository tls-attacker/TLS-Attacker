/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.certificate;

import de.rub.nds.tlsattacker.core.constants.CertificateKeyType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomPrivateKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomPublicKey;
import de.rub.nds.tlsattacker.core.util.CertificateUtils;
import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateException;
import org.bouncycastle.crypto.tls.Certificate;

public class CertificateKeyPair {
    
    private final CertificateKeyType certPublicKeyType;
    
    private final CertificateKeyType certSignatureType;
    
    private final byte[] certificateBytes;
    
    private final CustomPublicKey publicKey;
    
    private final CustomPrivateKey privateKey;

    private final NamedGroup signatureGroup;
    
    private final NamedGroup publicKeyGroup;

    public CertificateKeyPair(CertificateKeyType certPublicKeyType, CertificateKeyType certSignatureType, byte[] certificateBytes, CustomPublicKey publicKey, CustomPrivateKey privateKey, NamedGroup signatureGroup, NamedGroup publicKeyGroup) {
        this.certPublicKeyType = certPublicKeyType;
        this.certSignatureType = certSignatureType;
        this.certificateBytes = certificateBytes;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.signatureGroup = signatureGroup;
        this.publicKeyGroup = publicKeyGroup;
    }
    
    public CertificateKeyPair(CertificateKeyType certPublicKeyType, CertificateKeyType certSignatureType, File certFile, File privateKeyFile) throws CertificateException, IOException {
        this.certPublicKeyType = certPublicKeyType;
        this.certSignatureType = certSignatureType;
        Certificate certificate = PemUtil.readCertificate(certFile);
        this.publicKey = CertificateUtils.parseCustomPublicKey(certificate);
        this.privateKey = PemUtil.readPrivateKey(privateKeyFile);
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
}
