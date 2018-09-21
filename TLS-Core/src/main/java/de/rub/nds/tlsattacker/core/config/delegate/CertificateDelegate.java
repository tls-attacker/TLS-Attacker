/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.util.JKSLoader;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.util.KeystoreHandler;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import static org.apache.commons.lang3.StringUtils.join;
import org.bouncycastle.crypto.tls.Certificate;

public class CertificateDelegate extends Delegate {

    @Parameter(names = "-keystore", description = "Java Key Store (JKS) file to use as a certificate")
    private String keystore = null;

    @Parameter(names = "-password", description = "Java Key Store (JKS) file password")
    private String password = null;

    @Parameter(names = "-alias", description = "Alias of the key to be used from Java Key Store (JKS)")
    private String alias = null;

    public CertificateDelegate() {
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

    @Override
    public void applyDelegate(Config config) {
        Map<String, String> mandatoryParameters = new HashMap<>();
        mandatoryParameters.put("keystore", keystore);
        mandatoryParameters.put("password", password);
        mandatoryParameters.put("alias", alias);
        List<String> missingParameters = new ArrayList<>();
        for (String p : mandatoryParameters.keySet()) {
            if (mandatoryParameters.get(p) == null) {
                missingParameters.add(p);
            }
        }
        if (missingParameters.size() == 3) {
            return;
        } else if (!missingParameters.isEmpty()) {
            throw new ParameterException("The following parameters are required for loading a" + " keystore: "
                    + join(mandatoryParameters.keySet()));
        }
        try {
            ConnectionEndType type;
            switch (config.getDefaultRunningMode()) {
                case CLIENT:
                    type = ConnectionEndType.CLIENT;
                    break;
                case MITM:
                    throw new ConfigurationException("CertificateDelegate is not allowed for MitM running mode");
                case SERVER:
                    type = ConnectionEndType.SERVER;
                    break;
                default:
                    throw new ConfigurationException("Unknown RunningMode");
            }
            KeyStore store = KeystoreHandler.loadKeyStore(keystore, password);
            Certificate cert = JKSLoader.loadTLSCertificate(store, alias);
            PrivateKey privateKey = null;
            privateKey = (PrivateKey) store.getKey(alias, password.toCharArray());
            CertificateKeyPair pair = new CertificateKeyPair(cert, privateKey);
            pair.adjustInConfig(config, type);
            config.setAutoSelectCertificate(false);
        } catch (UnrecoverableKeyException | KeyStoreException | IOException | NoSuchAlgorithmException
                | CertificateException ex) {
            throw new ConfigurationException("Could not load private Key from Keystore", ex);
        }
    }
}
