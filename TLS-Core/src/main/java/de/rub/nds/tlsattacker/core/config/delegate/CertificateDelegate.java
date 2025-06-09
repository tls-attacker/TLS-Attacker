/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import static org.apache.commons.lang3.StringUtils.join;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.util.JKSLoader;
import de.rub.nds.tlsattacker.util.KeystoreHandler;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.interfaces.DHPrivateKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.tls.crypto.TlsCertificate;

public class CertificateDelegate extends Delegate {

    public static final int PREDEFINED_LEAF_CERT_INDEX = 0;

    private static final Logger LOGGER = LogManager.getLogger();

    @Parameter(names = "-cert", description = "PEM encoded certificate file")
    private String certificate = null;

    @Parameter(names = "-key", description = "PEM encoded private key")
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
        Map<String, String> mandatoryParameters = new HashMap<>();
        mandatoryParameters.put("keystore", keystore);
        mandatoryParameters.put("password", password);
        mandatoryParameters.put("alias", alias);

        PrivateKey privateKey = null;
        if (key != null) {
            LOGGER.debug("Loading private key");
            privateKey = PemUtil.readPrivateKey(new File(key));
            adjustPrivateKey(
                    config.getCertificateChainConfig().get(PREDEFINED_LEAF_CERT_INDEX), privateKey);
        }
        if (certificate != null) {
            if (privateKey == null) {
                LOGGER.warn("Certificate provided without chain");
            }
            LOGGER.debug("Loading certificate chain");
            try {
                List<CertificateBytes> byteList =
                        CertificateIo.readPemCertificateByteList(
                                new FileInputStream(new File(certificate)));
                config.setDefaultExplicitCertificateChain(byteList);
            } catch (Exception ex) {
                LOGGER.warn("Could not read certificate", ex);
            }
        }
        List<String> missingParameters = new ArrayList<>();
        for (Map.Entry<String, String> entry : mandatoryParameters.entrySet()) {
            if (entry.getValue() == null) {
                missingParameters.add(entry.getKey());
            }
        }
        if (missingParameters.size() == 3) {
            return;
        } else if (!missingParameters.isEmpty()) {
            throw new ParameterException(
                    "The following parameters are required for loading a"
                            + " keystore: "
                            + join(mandatoryParameters.keySet()));
        }
        try {
            KeyStore store = KeystoreHandler.loadKeyStore(keystore, password);
            TlsCertificate cert = JKSLoader.loadTLSCertificate(store, alias);
            privateKey = (PrivateKey) store.getKey(alias, password.toCharArray());
            List<CertificateBytes> byteList = List.of(new CertificateBytes(cert.getEncoded()));

            config.setDefaultExplicitCertificateChain(byteList);
            adjustPrivateKey(config.getCertificateChainConfig().getFirst(), privateKey);
        } catch (UnrecoverableKeyException
                | KeyStoreException
                | IOException
                | NoSuchAlgorithmException
                | CertificateException ex) {
            throw new ConfigurationException("Could not load private Key from Keystore", ex);
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
