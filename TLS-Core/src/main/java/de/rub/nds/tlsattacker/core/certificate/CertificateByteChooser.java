/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.certificate;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CertificateKeyType;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
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

    private final static String RESOURCE_PATH = "certs/";

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

    private List<String> getResourceFiles(String path) throws IOException {
        List<String> filenames = new ArrayList<>();
        filenames.add("ec_rsa_sect163r1_cert.pem");
        filenames.add("ec_secp224k1_cert.pem");
        filenames.add("ec_sect571k1_cert.pem");
        filenames.add("ec_rsa_secp160r2_cert.pem");
        filenames.add("ec_rsa_sect409k1_cert.pem");
        filenames.add("ec_sect193r2_cert.pem");
        filenames.add("dh_dsa_cert.pem");
        filenames.add("ec_rsa_sect163r2_cert.pem");
        filenames.add("ec_secp224r1_cert.pem");
        filenames.add("ec_sect571r1_cert.pem");
        filenames.add("ec_rsa_secp192k1_cert.pem");
        filenames.add("ec_rsa_sect409r1_cert.pem");
        filenames.add("ec_sect233k1_cert.pem");
        filenames.add("dh_rsa_cert.pem");
        filenames.add("ec_rsa_sect193r1_cert.pem");
        filenames.add("ec_secp256k1_cert.pem");
        filenames.add("rsa1024_cert.pem");
        filenames.add("ec_rsa_secp224k1_cert.pem");
        filenames.add("ec_rsa_sect571k1_cert.pem");
        filenames.add("ec_sect233r1_cert.pem");
        filenames.add("dsa1024_cert.pem");
        filenames.add("ec_rsa_sect193r2_cert.pem");
        filenames.add("ec_secp384r1_cert.pem");
        filenames.add("rsa2048_cert.pem");
        filenames.add("ec_rsa_secp224r1_cert.pem");
        filenames.add("ec_rsa_sect571r1_cert.pem");
        filenames.add("ec_sect239k1_cert.pem");
        filenames.add("dsa2048_cert.pem");
        filenames.add("ec_rsa_sect233k1_cert.pem");
        filenames.add("ec_secp521r1_cert.pem");
        filenames.add("rsa4096_cert.pem");
        filenames.add("ec_rsa_secp256k1_cert.pem");
        filenames.add("ec_secp160k1_cert.pem");
        filenames.add("ec_sect283k1_cert.pem");
        filenames.add("dsa3072_cert.pem");
        filenames.add("ec_rsa_sect233r1_cert.pem");
        filenames.add("ec_sect163k1_cert.pem");
        filenames.add("rsa512_cert.pem");
        filenames.add("ec_rsa_secp384r1_cert.pem");
        filenames.add("ec_secp160r1_cert.pem");
        filenames.add("ec_sect283r1_cert.pem");
        filenames.add("dsa512_cert.pem");
        filenames.add("ec_rsa_sect239k1_cert.pem");
        filenames.add("ec_sect163r1_cert.pem");
        filenames.add("ec_rsa_secp521r1_cert.pem");
        filenames.add("ec_secp160r2_cert.pem");
        filenames.add("ec_sect409k1_cert.pem");
        filenames.add("ec_rsa_secp160k1_cert.pem");
        filenames.add("ec_rsa_sect283k1_cert.pem");
        filenames.add("ec_sect163r2_cert.pem");
        filenames.add("ec_rsa_sect163k1_cert.pem");
        filenames.add("ec_secp192k1_cert.pem");
        filenames.add("ec_sect409r1_cert.pem");
        filenames.add("ec_rsa_secp160r1_cert.pem");
        filenames.add("ec_rsa_sect283r1_cert.pem");
        filenames.add("ec_sect193r1_cert.pem");
        filenames.add("ec_secp256r1_cert.pem");
        filenames.add("ec_rsa_secp256r1_cert.pem");
        filenames.add("ec_rsa_cert_secp256r1.pem");
        return filenames;
    }

    private void loadKeys() {
        try {
            for (String file : getResourceFiles(RESOURCE_PATH)) {
                if (file.endsWith("cert.pem")) {
                    try {
                        Certificate readCertificate = PemUtil.readCertificate(this.getClass().getClassLoader()
                                .getResourceAsStream(RESOURCE_PATH + file));
                        String keyName = file.replace("cert.pem", "key.pem");
                        PrivateKey privateKey = PemUtil.readPrivateKey(this.getClass().getClassLoader()
                                .getResourceAsStream(RESOURCE_PATH + keyName));
                        keyPairList.add(new CertificateKeyPair(readCertificate, privateKey));
                    } catch (Exception E) {
                        LOGGER.warn("Could not load: " + file, E);
                    }
                }
            }
        } catch (IOException E) {
            throw new RuntimeException("Could not load ResourcePath: " + RESOURCE_PATH, E);
        }
    }

    public List<CertificateKeyPair> getCertificateKeyPairList() {
        return Collections.unmodifiableList(keyPairList);
    }

    public CertificateKeyPair chooseCertificateKeyPair(Chooser chooser) {
        if (!chooser.getConfig().isAutoSelectCertificate()) {
            return chooser.getConfig().getDefaultExplicitCertificateKeyPair();
        }
        KeyExchangeAlgorithm keyExchangeAlgorithm = AlgorithmResolver.getKeyExchangeAlgorithm(chooser
                .getSelectedCipherSuite());
        NamedGroup namedGroup = chooser.getSelectedNamedGroup();

        CertificateKeyType neededPublicKeyType = keyExchangeAlgorithm.getRequiredCertPublicKeyType();

        CertificateKeyType prefereredSignatureCertSignatureType = chooser.getConfig()
                .getPreferedCertificateSignatureType();
        switch (keyExchangeAlgorithm) {
            case DH_DSS:
                if (prefereredSignatureCertSignatureType != CertificateKeyType.DSS) {
                    LOGGER.warn("PreferedSignatureType does not match Ciphersuite - ignoring preference");
                    prefereredSignatureCertSignatureType = CertificateKeyType.DSS;

                }
                break;
            case DH_RSA:
                if (prefereredSignatureCertSignatureType != CertificateKeyType.RSA) {
                    LOGGER.warn("PreferedSignatureType does not match Ciphersuite - ignoring preference");
                    prefereredSignatureCertSignatureType = CertificateKeyType.RSA;

                }
                prefereredSignatureCertSignatureType = CertificateKeyType.RSA;
                break;
            case ECDHE_ECDSA:
            case ECDH_ECDSA:
            case ECMQV_ECDSA:
            case CECPQ1_ECDSA:
                if (prefereredSignatureCertSignatureType != CertificateKeyType.ECDSA) {
                    LOGGER.warn("PreferedSignatureType does not match Ciphersuite - ignoring preference");
                    prefereredSignatureCertSignatureType = CertificateKeyType.ECDSA;
                }
        }
        CertificateKeyPair nextBestChoice = null;
        for (CertificateKeyPair pair : keyPairList) {
            if (pair.getCertPublicKeyType() == neededPublicKeyType
                    && pair.getCertSignatureType() == prefereredSignatureCertSignatureType) {
                nextBestChoice = pair;
                if (neededPublicKeyType == CertificateKeyType.ECDSA) {
                    if (pair.getSignatureGroup() == null) {
                        if (namedGroup == pair.getSignatureGroup()) {
                            return pair;
                        }
                    }
                    if (namedGroup != pair.getPublicKeyGroup() || pair.getSignatureGroup() != pair.getSignatureGroup()) {
                        continue;
                    }
                }
                return pair;
            }

        }
        if (nextBestChoice != null) {
            LOGGER.warn("Could not find a fitting Certificate - ignoreing preferences...");
            return nextBestChoice;
        }
        LOGGER.warn("Could not find a matching CertificateKeyPair - returning first in List");
        if (keyPairList.isEmpty()) {
            throw new RuntimeException("Key Pair list is empty!");
        }
        return keyPairList.get(0);
    }
}
