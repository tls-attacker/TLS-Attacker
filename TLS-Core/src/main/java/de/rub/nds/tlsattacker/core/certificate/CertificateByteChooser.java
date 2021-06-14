/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.certificate;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CertificateKeyType;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.IOException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.tls.Certificate;

public class CertificateByteChooser {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String RESOURCE_PATH = "certs/";

    private static CertificateByteChooser instance;

    public static synchronized CertificateByteChooser getInstance() {
        if (instance == null) {
            instance = new CertificateByteChooser();
        }
        return instance;
    }

    private final List<CertificateKeyPair> keyPairList;

    private CertificateByteChooser() {
        keyPairList = new LinkedList<>();
        loadKeys();
    }

    private List<String> getResourceFiles() throws IOException {
        List<String> filenames = new ArrayList<>();
        filenames.add("ec_sect163r1_rsa_cert.pem");
        filenames.add("ec_secp224k1_ecdsa_cert.pem");
        filenames.add("ec_sect571k1_ecdsa_cert.pem");
        filenames.add("ec_secp160r2_rsa_cert.pem");
        filenames.add("ec_sect409k1_rsa_cert.pem");
        filenames.add("ec_sect193r2_ecdsa_cert.pem");
        filenames.add("dh3072_dsa_cert.pem");
        filenames.add("dh2048_dsa_cert.pem");
        filenames.add("dh1024_dsa_cert.pem");
        filenames.add("dh512_dsa_cert.pem");
        filenames.add("ec_sect163r2_rsa_cert.pem");
        filenames.add("ec_secp224r1_ecdsa_cert.pem");
        filenames.add("ec_sect571r1_ecdsa_cert.pem");
        filenames.add("ec_secp192k1_rsa_cert.pem");
        filenames.add("ec_sect409r1_rsa_cert.pem");
        filenames.add("ec_sect233k1_ecdsa_cert.pem");
        filenames.add("dh3072_rsa_cert.pem");
        filenames.add("dh2048_rsa_cert.pem");
        filenames.add("dh1024_rsa_cert.pem");
        filenames.add("dh512_rsa_cert.pem");
        filenames.add("ec_sect193r1_rsa_cert.pem");
        filenames.add("ec_secp256k1_ecdsa_cert.pem");
        filenames.add("rsa1024_rsa_cert.pem");
        filenames.add("ec_secp224k1_rsa_cert.pem");
        filenames.add("ec_sect571k1_rsa_cert.pem");
        filenames.add("ec_sect233r1_ecdsa_cert.pem");
        filenames.add("dsa1024_rsa_cert.pem");
        filenames.add("ec_sect193r2_rsa_cert.pem");
        filenames.add("ec_secp384r1_ecdsa_cert.pem");
        filenames.add("rsa2048_rsa_cert.pem");
        filenames.add("ec_secp224r1_rsa_cert.pem");
        filenames.add("ec_sect571r1_rsa_cert.pem");
        filenames.add("ec_sect239k1_ecdsa_cert.pem");
        filenames.add("dsa2048_rsa_cert.pem");
        filenames.add("ec_sect233k1_rsa_cert.pem");
        filenames.add("ec_secp521r1_ecdsa_cert.pem");
        filenames.add("rsa4096_rsa_cert.pem");
        filenames.add("ec_secp256k1_rsa_cert.pem");
        filenames.add("ec_secp160k1_ecdsa_cert.pem");
        filenames.add("ec_sect283k1_ecdsa_cert.pem");
        filenames.add("dsa3072_rsa_cert.pem");
        filenames.add("ec_sect233r1_rsa_cert.pem");
        filenames.add("ec_sect163k1_ecdsa_cert.pem");
        filenames.add("rsa512_rsa_cert.pem");
        filenames.add("ec_secp384r1_rsa_cert.pem");
        filenames.add("ec_secp160r1_ecdsa_cert.pem");
        filenames.add("ec_sect283r1_ecdsa_cert.pem");
        filenames.add("dsa512_rsa_cert.pem");
        filenames.add("ec_sect239k1_rsa_cert.pem");
        filenames.add("ec_sect163r1_ecdsa_cert.pem");
        filenames.add("ec_secp521r1_rsa_cert.pem");
        filenames.add("ec_secp160r2_ecdsa_cert.pem");
        filenames.add("ec_sect409k1_ecdsa_cert.pem");
        filenames.add("ec_secp160k1_rsa_cert.pem");
        filenames.add("ec_sect283k1_rsa_cert.pem");
        filenames.add("ec_sect163r2_ecdsa_cert.pem");
        filenames.add("ec_sect163k1_rsa_cert.pem");
        filenames.add("ec_secp192k1_ecdsa_cert.pem");
        filenames.add("ec_sect409r1_ecdsa_cert.pem");
        filenames.add("ec_secp160r1_rsa_cert.pem");
        filenames.add("ec_sect283r1_rsa_cert.pem");
        filenames.add("ec_sect193r1_ecdsa_cert.pem");
        filenames.add("ec_secp256r1_ecdsa_cert.pem");
        filenames.add("ec_secp256r1_rsa_cert.pem");
        filenames.add("dh3072_ecdsa_cert.pem");
        filenames.add("dh2048_ecdsa_cert.pem");
        filenames.add("dh1024_ecdsa_cert.pem");
        filenames.add("dh512_ecdsa_cert.pem");
        // filenames.add("gost01_0_cert.pem");
        filenames.add("gost01_A_cert.pem");
        filenames.add("gost01_B_cert.pem");
        filenames.add("gost01_C_cert.pem");
        filenames.add("gost01_XA_cert.pem");
        filenames.add("gost01_XB_cert.pem");
        // filenames.add("gost12_256_0_cert.pem");
        filenames.add("gost12_256_A_cert.pem");
        filenames.add("gost12_256_B_cert.pem");
        filenames.add("gost12_256_C_cert.pem");
        filenames.add("gost12_512_A_cert.pem");
        filenames.add("gost12_512_B_cert.pem");
        filenames.add("gost12_256_XA_cert.pem");
        filenames.add("gost12_256_XB_cert.pem");

        return filenames;
    }

    private void loadKeys() {
        try {
            for (String file : getResourceFiles()) {
                if (file.endsWith("cert.pem")) {
                    try {
                        Certificate readCertificate = PemUtil.readCertificate(
                            this.getClass().getClassLoader().getResourceAsStream(RESOURCE_PATH + file));
                        String keyName = resolveKeyfileFromCert(file);
                        PrivateKey privateKey = PemUtil.readPrivateKey(
                            this.getClass().getClassLoader().getResourceAsStream(RESOURCE_PATH + keyName));
                        keyPairList.add(new CertificateKeyPair(readCertificate, privateKey));
                    } catch (Exception e) {
                        LOGGER.warn("Could not load: " + file, e);
                    }
                }
            }
        } catch (IOException e) {
            throw new RuntimeException("Could not load ResourcePath: " + RESOURCE_PATH, e);
        }
    }

    public List<CertificateKeyPair> getCertificateKeyPairList() {
        return Collections.unmodifiableList(keyPairList);
    }

    public CertificateKeyPair chooseCertificateKeyPair(Chooser chooser) {
        if (!chooser.getConfig().isAutoSelectCertificate()) {
            return chooser.getConfig().getDefaultExplicitCertificateKeyPair();
        }

        NamedGroup namedGroup = chooser.getSelectedNamedGroup();

        CertificateKeyType preferredSignatureCertSignatureType =
            chooser.getConfig().getPreferredCertificateSignatureType();

        CertificateKeyType neededPublicKeyType;
        KeyExchangeAlgorithm keyExchangeAlgorithm =
            AlgorithmResolver.getKeyExchangeAlgorithm(chooser.getSelectedCipherSuite());
        if (chooser.getSelectedProtocolVersion().isTLS13() || keyExchangeAlgorithm == null) {
            neededPublicKeyType = preferredSignatureCertSignatureType;
        } else {
            switch (keyExchangeAlgorithm) {
                case DH_RSA:
                case DHE_RSA:
                case ECDH_RSA:
                case ECDHE_RSA:
                case RSA:
                case SRP_SHA_RSA:
                case PSK_RSA:
                    if (preferredSignatureCertSignatureType != CertificateKeyType.RSA) {
                        LOGGER.warn("PreferredSignatureType does not match Cipher suite - ignoring preference");
                    }
                    preferredSignatureCertSignatureType = CertificateKeyType.RSA;
                    break;
                case ECDHE_ECDSA:
                case ECDH_ECDSA:
                case ECMQV_ECDSA:
                case CECPQ1_ECDSA:
                    if (preferredSignatureCertSignatureType != CertificateKeyType.ECDSA) {
                        LOGGER.warn("PreferredSignatureType does not match Cipher suite - ignoring preference");
                    }
                    preferredSignatureCertSignatureType = CertificateKeyType.ECDSA;
                    break;
                case DHE_DSS:
                case DH_DSS:
                case SRP_SHA_DSS:
                    if (preferredSignatureCertSignatureType != CertificateKeyType.DSS) {
                        LOGGER.warn("PreferredSignatureType does not match Cipher suite - ignoring preference");
                    }
                    preferredSignatureCertSignatureType = CertificateKeyType.DSS;
                    break;
                case VKO_GOST01:
                    if (preferredSignatureCertSignatureType != CertificateKeyType.GOST01) {
                        LOGGER.warn("PreferredSignatureType does not match Cipher suite - ignoring preference");
                    }
                    preferredSignatureCertSignatureType = CertificateKeyType.GOST01;
                    break;
                case VKO_GOST12:
                    if (preferredSignatureCertSignatureType != CertificateKeyType.GOST01) {
                        LOGGER.warn("PreferredSignatureType does not match Cipher suite - ignoring preference");
                    }
                    preferredSignatureCertSignatureType = CertificateKeyType.GOST12;
                    break;
                default:
                    LOGGER.warn("CipherSuite does not specify a certificate kex. Using  RSA.");
                    keyExchangeAlgorithm = KeyExchangeAlgorithm.RSA;
            }
            neededPublicKeyType = AlgorithmResolver.getCertificateKeyType(chooser.getSelectedCipherSuite());
        }

        CertificateKeyPair nextBestChoice = null;
        for (CertificateKeyPair pair : keyPairList) {
            if (pair.isUsable(neededPublicKeyType, preferredSignatureCertSignatureType)) {

                nextBestChoice = pair;
                if (neededPublicKeyType == CertificateKeyType.ECDSA || neededPublicKeyType == CertificateKeyType.ECDH) {
                    if (pair.getSignatureGroup() == null) {
                        if (namedGroup == pair.getSignatureGroup()) {
                            return pair;
                        }
                    }
                    if (namedGroup != pair.getPublicKeyGroup()
                        || pair.getSignatureGroup() != pair.getSignatureGroup()) {
                        continue;
                    }
                }

                SignatureAndHashAlgorithm sigHashAlgo = SignatureAndHashAlgorithm.forCertificateKeyPair(pair, chooser);
                if (neededPublicKeyType == CertificateKeyType.RSA
                    && sigHashAlgo.getSignatureAlgorithm().toString().startsWith("RSA_PSS")
                    && sigHashAlgo.getHashAlgorithm() == HashAlgorithm.SHA512 && pair.getPublicKey().keySize() < 2048) {
                    continue;
                }
                if (neededPublicKeyType == CertificateKeyType.RSA
                    && pair.getPublicKey().keySize() != chooser.getConfig().getPrefferedCertRsaKeySize()) {
                    continue;
                } else if (neededPublicKeyType == CertificateKeyType.DSS
                    && pair.getPublicKey().keySize() != chooser.getConfig().getPrefferedCertDssKeySize()) {
                    continue;
                }
                return pair;
            }

        }
        if (nextBestChoice != null) {
            LOGGER.warn("Could not find a fitting Certificate - ignoring preferences...");
            return nextBestChoice;
        }
        LOGGER.warn("Could not find a matching CertificateKeyPair - returning first in List");
        if (keyPairList.isEmpty()) {
            throw new RuntimeException("Key Pair list is empty!");
        }
        return keyPairList.get(0);
    }

    private String resolveKeyfileFromCert(String certName) {
        int signatureTypeSuffixIndex;
        if (certName.startsWith("ec_")) {
            signatureTypeSuffixIndex = certName.indexOf("_", 4);
            return certName.substring(0, signatureTypeSuffixIndex) + "_key.pem";
        } else if (certName.startsWith("rsa") || certName.startsWith("dh") || certName.startsWith("dsa")) {
            signatureTypeSuffixIndex = certName.indexOf("_");
            return certName.substring(0, signatureTypeSuffixIndex) + "_key.pem";
        } else {
            return certName.replace("cert.pem", "key.pem");
        }
    }
}
