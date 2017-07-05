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
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.util.JKSLoader;
import de.rub.nds.tlsattacker.core.config.TlsConfig;
import de.rub.nds.tlsattacker.util.KeystoreHandler;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateDelegate extends Delegate {

    @Parameter(names = "-keystore", description = "Java Key Store (JKS) file to use as a certificate. In case TLS Client is used, the client sends ClientCertificate in the TLS handshake. Use keyword empty to enforce an empty ClientCertificate message.")
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
    public void applyDelegate(TlsConfig config) {
        if (password != null) {
            config.setPassword(password);
        }
        if (alias != null) {
            config.setAlias(alias);
        }
        try {
            if (keystore != null) {
                config.setKeyStore(KeystoreHandler.loadKeyStore(keystore, config.getPassword()));
                config.setOurCertificate(JKSLoader.loadTLSCertificate(config.getKeyStore(), alias));
                try {
                    config.setPrivateKey((PrivateKey) config.getKeyStore().getKey(config.getAlias(),
                            config.getAlias().toCharArray()));
                } catch (UnrecoverableKeyException ex) {
                    LOGGER.warn("Could not load private Key from Keystore", ex);
                }
            }
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
            throw new ConfigurationException("Could not load Keystore at: " + keystore, ex);
        }
    }
}
