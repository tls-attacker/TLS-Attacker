/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import de.rub.nds.protocol.exception.ConfigurationException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.util.JKSLoader;
import de.rub.nds.tlsattacker.util.KeystoreHandler;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.filesystem.CertificateBytes;
import de.rub.nds.x509attacker.filesystem.CertificateIo;
import de.rub.nds.x509attacker.signatureengine.keyparsers.PemUtil;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.LinkedList;
import java.util.List;
import javax.crypto.interfaces.DHPrivateKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.tls.crypto.TlsCertificate;

public class CertificateDelegate extends Delegate {

    public static final int PREDEFINED_LEAF_CERT_INDEX = 0;

    private static final Logger LOGGER = LogManager.getLogger();

    @Parameter(
            names = "-cert",
            description =
                    "PEM encoded certificate file (can contain multiple certificates for a certificate chain) or comma-separated list of full certificate chain files")
    private String certificate = null;

    @Parameter(
            names = "-key",
            description = "PEM encoded private key or comma-separated list of private key files")
    private String key = null;

    @Parameter(
            names = "-keystore",
            description = "Java Key Store (JKS) file to use as a certificate")
    private String keystore = null;

    @Parameter(names = "-password", description = "Java Key Store (JKS) file password")
    private String password = null;

    @Parameter(
            names = "-alias",
            description = "Alias of the key to be used from Java Key Store (JKS)")
    private String alias = null;

    public CertificateDelegate() {
        // Default Constructor
    }

    public String getKeystore() {
        return keystore;
    }

    public void setKeystore(String keystore) {
        this.keystore = keystore;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public String getCertificate() {
        return certificate;
    }

    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    @Override
    public void applyDelegate(Config config) {
        // For now, we only support either listed cert files OR a keystore
        if (certKeyParametersProvided()) {
            LOGGER.debug("Using certificate material from provided cert and key files");
            applyCertKeyPaths(config);
        } else if (keystoreParametersProvided()) {
            LOGGER.debug("Using certificate material from provided keystore");
            applyKeystore(config);
        } else if (anyParameterSet()) {
            throw new ParameterException(
                    "Missing parameters for certificates. Either provide paths to the certificates and keys or a keystore along with the password and certificate alias.");
        }
    }

    private void applyKeystore(Config config) {
        try {
            KeyStore store = KeystoreHandler.loadKeyStore(keystore, password);
            TlsCertificate cert = JKSLoader.loadTLSCertificate(store, alias);
            PrivateKey privateKey = (PrivateKey) store.getKey(alias, password.toCharArray());
            List<CertificateBytes> byteList = List.of(new CertificateBytes(cert.getEncoded()));

            config.setDefaultCertificateChainBytes(List.of(byteList));
            adjustPrivateKey(
                    config.getCertificateChainConfigs().get(0).get(PREDEFINED_LEAF_CERT_INDEX),
                    privateKey);
        } catch (UnrecoverableKeyException
                | KeyStoreException
                | IOException
                | NoSuchAlgorithmException
                | CertificateException ex) {
            throw new ConfigurationException("Could not load private Key from Keystore", ex);
        }
    }

    private boolean anyParameterSet() {
        return certificate != null
                || key != null
                || password != null
                || keystore != null
                || alias != null;
    }

    private boolean certKeyParametersProvided() {
        return certificate != null && key != null;
    }

    private boolean keystoreParametersProvided() {
        return keystore != null && password != null && alias != null;
    }

    private void applyCertKeyPaths(Config config) {
        String[] certPaths = certificate.split(",");
        String[] keyPaths = key.split(",");

        if (keyPaths.length != certPaths.length) {
            throw new ParameterException(
                    "Number of certificate files ("
                            + certPaths.length
                            + ") must match number of key files ("
                            + keyPaths.length
                            + ")");
        }

        List<List<CertificateBytes>> allExplicitChains = new LinkedList<>();
        config.getCertificateChainConfigs().clear();
        for (int i = 0; i < certPaths.length; i++) {
            String certPath = certPaths[i].trim();

            if (i < keyPaths.length) {
                String keyPath = keyPaths[i].trim();
                LOGGER.debug("Loading private key from {}", keyPath);
                PrivateKey privateKey = PemUtil.readPrivateKey(new File(keyPath));
                X509CertificateConfig leafConfig = new X509CertificateConfig();
                leafConfig.setPublicKeyType(getPublicKeyType(privateKey));
                adjustPrivateKey(leafConfig, privateKey);
                List<X509CertificateConfig> chainConfig = new LinkedList<>();
                chainConfig.add(leafConfig);
                config.getCertificateChainConfigs().add(chainConfig);
            }

            LOGGER.debug("Loading certificate chain from {}", certPath);
            try (FileInputStream inputStream = new FileInputStream(certPath)) {
                List<CertificateBytes> byteList =
                        CertificateIo.readPemCertificateByteList(inputStream);
                allExplicitChains.add(byteList);
            } catch (Exception ex) {
                LOGGER.warn("Could not read certificate file: " + certPath, ex);
            }
        }

        config.setDefaultCertificateChainBytes(allExplicitChains);
    }

    private X509PublicKeyType getPublicKeyType(PrivateKey privateKey) {
        if (privateKey instanceof RSAPrivateKey) {
            return X509PublicKeyType.RSA;
        } else if (privateKey instanceof ECPrivateKey) {
            return X509PublicKeyType.ECDH_ECDSA;
        } else if (privateKey instanceof DSAPrivateKey) {
            return X509PublicKeyType.DSA;
        } else if (privateKey instanceof DHPrivateKey) {
            return X509PublicKeyType.DH;
        } else {
            throw new UnsupportedOperationException(
                    "Unsupported private key type: " + privateKey.getClass().getName());
        }
    }

    private void adjustPrivateKey(X509CertificateConfig config, PrivateKey privateKey) {
        if (privateKey instanceof RSAPrivateKey) {
            RSAPrivateKey rsaKey = (RSAPrivateKey) privateKey;
            config.setDefaultSubjectRsaPrivateExponent(rsaKey.getPrivateExponent());
            config.setDefaultSubjectRsaModulus(rsaKey.getModulus());
        } else if (privateKey instanceof DSAPrivateKey) {
            DSAPrivateKey dsaKey = (DSAPrivateKey) privateKey;
            config.setDefaultSubjectDsaGenerator(dsaKey.getParams().getG());
            config.setDefaultSubjectDsaPrimeP(dsaKey.getParams().getP());
            config.setDefaultSubjectDsaPrimeQ(dsaKey.getParams().getQ());
            config.setDefaultSubjectDsaPrivateKey(dsaKey.getX());
        } else if (privateKey instanceof DHPrivateKey) {
            DHPrivateKey dhKey = (DHPrivateKey) privateKey;
            config.setDefaultSubjectDhPrivateKey(dhKey.getX());
            config.setDhModulus(dhKey.getParams().getP());
            config.setDhGenerator(dhKey.getParams().getG());
        } else if (privateKey instanceof ECPrivateKey) {
            ECPrivateKey ecKey = (ECPrivateKey) privateKey;
            config.setDefaultSubjectEcPrivateKey(ecKey.getS());
            config.setDefaultSubjectNamedCurve(X509NamedCurve.getX509NamedCurve(ecKey));
        } else {
            throw new UnsupportedOperationException("This private key is not supported:" + key);
        }
    }
}
