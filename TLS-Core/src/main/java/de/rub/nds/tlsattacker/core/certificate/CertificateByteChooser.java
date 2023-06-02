/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate;

import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.IOException;
import java.io.InputStream;
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

    private static final int WORST_CERTIFICATE_RATING = Integer.MAX_VALUE;
    private static final int BEST_POSSIBLE_CERTIFICATE_RATING = 1;
    private static final int INVALID_CERTIFICATE_RATING = 0;

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
        filenames.add("ec_sect193r2_rsa_cert.pem");
        filenames.add("ec_secp384r1_ecdsa_cert.pem");
        filenames.add("rsa2048_rsa_cert.pem");
        filenames.add("ec_secp224r1_rsa_cert.pem");
        filenames.add("ec_sect571r1_rsa_cert.pem");
        filenames.add("ec_sect239k1_ecdsa_cert.pem");
        filenames.add("ec_sect233k1_rsa_cert.pem");
        filenames.add("ec_secp521r1_ecdsa_cert.pem");
        filenames.add("rsa4096_rsa_cert.pem");
        filenames.add("ec_secp256k1_rsa_cert.pem");
        filenames.add("ec_secp160k1_ecdsa_cert.pem");
        filenames.add("ec_sect283k1_ecdsa_cert.pem");
        filenames.add("ec_sect233r1_rsa_cert.pem");
        filenames.add("ec_sect163k1_ecdsa_cert.pem");
        filenames.add("rsa512_rsa_cert.pem");
        filenames.add("ec_secp384r1_rsa_cert.pem");
        filenames.add("ec_secp160r1_ecdsa_cert.pem");
        filenames.add("ec_sect283r1_ecdsa_cert.pem");
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
        filenames.add("dsa512_rsa_cert.pem");
        filenames.add("dsa1024_rsa_cert.pem");
        filenames.add("dsa2048_rsa_cert.pem");
        filenames.add("dsa3072_rsa_cert.pem");
        filenames.add("dsa512_ecdsa_cert.pem");
        filenames.add("dsa1024_ecdsa_cert.pem");
        filenames.add("dsa2048_ecdsa_cert.pem");
        filenames.add("dsa3072_ecdsa_cert.pem");
        filenames.add("dsa512_dsa_cert.pem");
        filenames.add("dsa1024_dsa_cert.pem");
        filenames.add("dsa2048_dsa_cert.pem");
        filenames.add("dsa3072_dsa_cert.pem");
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
                    String keyName = resolveKeyfileFromCert(file);
                    try (InputStream certInputStream =
                                    this.getClass()
                                            .getClassLoader()
                                            .getResourceAsStream(RESOURCE_PATH + file);
                            InputStream keyInputStream =
                                    this.getClass()
                                            .getClassLoader()
                                            .getResourceAsStream(RESOURCE_PATH + keyName)) {
                        Certificate readCertificate = PemUtil.readCertificate(certInputStream);
                        PrivateKey privateKey = PemUtil.readPrivateKey(keyInputStream);
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

        Integer bestRating = WORST_CERTIFICATE_RATING;
        CertificateKeyPair bestKeyPair = null;
        for (CertificateKeyPair keyPair : keyPairList) {
            Integer newRating = rateKeyPair(keyPair, chooser);
            if (newRating != INVALID_CERTIFICATE_RATING) {
                if (newRating == BEST_POSSIBLE_CERTIFICATE_RATING) {
                    bestKeyPair = keyPair;
                    break;
                }
                if (newRating < bestRating) {
                    bestRating = newRating;
                    bestKeyPair = keyPair;
                }
            }
        }
        if (bestKeyPair != null) {
            LOGGER.debug(
                    "Choosing Certificate: {}(Group:{}),{}",
                    bestKeyPair.getCertPublicKeyType(),
                    bestKeyPair.getPublicKeyGroup(),
                    bestKeyPair.getSignatureAndHashAlgorithm());
            return bestKeyPair;
        }

        LOGGER.warn(
                "No appropriate Certificate Found. Using Default ({}; {}).",
                chooser.getConfig().getDefaultExplicitCertificateKeyPair().getCertPublicKeyType(),
                chooser.getConfig()
                        .getDefaultExplicitCertificateKeyPair()
                        .getSignatureAndHashAlgorithm());
        return chooser.getConfig().getDefaultExplicitCertificateKeyPair();
    }

    /**
     * Determines a rating based on the position of offered algorithms in the respective ClientHello
     * lists. A lower rating is better.
     */
    private Integer rateKeyPair(CertificateKeyPair keyPair, Chooser chooser) {
        List<SignatureAndHashAlgorithm> clientSupportedAlgorithms =
                chooser.getClientSupportedCertificateSignAlgorithms();
        if (chooser.getContext().getTlsContext().getClientSupportedCertificateSignAlgorithms()
                != null) {
            clientSupportedAlgorithms = chooser.getClientSupportedSignatureAndHashAlgorithms();
        }

        if (keyPair.isCompatibleWithCipherSuite(chooser)) {
            Integer sigAlgRating = 1;
            if (!clientSupportedAlgorithms.isEmpty()) {
                sigAlgRating =
                        clientSupportedAlgorithms.indexOf(keyPair.getSignatureAndHashAlgorithm())
                                + 1;
            }
            Integer groupRating;
            if (keyPair.getPublicKeyGroup() != null) {
                groupRating =
                        chooser.getClientSupportedNamedGroups().indexOf(keyPair.getPublicKeyGroup())
                                + 1;
            } else {
                if (isBadKeySize(keyPair, chooser)) {
                    groupRating = chooser.getClientSupportedNamedGroups().size() + 1;
                } else {
                    groupRating = 1;
                }
            }
            return sigAlgRating * groupRating;
        } else {
            return INVALID_CERTIFICATE_RATING;
        }
    }

    private Boolean isBadKeySize(CertificateKeyPair keyPair, Chooser chooser) {
        Boolean badRsaKeySize =
                (keyPair.getCertPublicKeyType() == CertificateKeyType.RSA
                        && keyPair.getPublicKey().keySize()
                                != chooser.getConfig().getPreferredCertRsaKeySize());
        Boolean badDssKeySize =
                (keyPair.getCertPublicKeyType() == CertificateKeyType.DSS
                        && keyPair.getPublicKey().keySize()
                                != chooser.getConfig().getPreferredCertDssKeySize());
        return badRsaKeySize || badDssKeySize;
    }

    private String resolveKeyfileFromCert(String certName) {
        int signatureTypeSuffixIndex;
        if (certName.startsWith("ec_")) {
            signatureTypeSuffixIndex = certName.indexOf("_", 4);
            return certName.substring(0, signatureTypeSuffixIndex) + "_key.pem";
        } else if (certName.startsWith("rsa")
                || certName.startsWith("dh")
                || certName.startsWith("dsa")) {
            signatureTypeSuffixIndex = certName.indexOf("_");
            return certName.substring(0, signatureTypeSuffixIndex) + "_key.pem";
        } else {
            return certName.replace("cert.pem", "key.pem");
        }
    }
}
