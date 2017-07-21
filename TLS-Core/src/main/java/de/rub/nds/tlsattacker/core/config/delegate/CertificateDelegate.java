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
import de.rub.nds.tlsattacker.core.crypto.ec.CustomECPoint;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.util.CertificateUtils;
import de.rub.nds.tlsattacker.core.util.CurveNameRetriever;
import de.rub.nds.tlsattacker.core.util.JKSLoader;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.util.KeystoreHandler;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.tls.Certificate;

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
    public void applyDelegate(Config config) {
        try {
            if (keystore != null && password != null && alias != null) {
                KeyStore store = KeystoreHandler.loadKeyStore(keystore, password);
                Certificate cert = JKSLoader.loadTLSCertificate(store, alias);
                PrivateKey key = null;
                try {
                    key = (PrivateKey) store.getKey(alias, password.toCharArray());
                } catch (UnrecoverableKeyException ex) {
                    throw new ConfigurationException("Could not load private Key from Keystore", ex);
                }
                ByteArrayOutputStream stream = new ByteArrayOutputStream();
                cert.encode(stream);
                try {
                    if (CertificateUtils.hasDHParameters(cert)) {
                        DHPublicKeyParameters dhParameters = CertificateUtils.extractDHPublicKeyParameters(cert);
                        applyDHParameters(config, dhParameters);
                        config.setDefaultDsaCertificate(stream.toByteArray());// TODO
                    } else if (CertificateUtils.hasECParameters(cert)) {
                        ECPublicKeyParameters ecParameters = CertificateUtils.extractECPublicKeyParameters(cert);
                        applyECParameters(config, ecParameters);
                        config.setDefaultEcCertificate(stream.toByteArray());
                    } else if (CertificateUtils.hasRSAParameters(cert)) {
                        applyRSAParameters(config, CertificateUtils.extractRSAModulus(cert),
                                CertificateUtils.extractRSAPublicKey(cert));
                        config.setDefaultRsaCertificate(stream.toByteArray());
                    }
                } catch (IOException E) {
                    throw new ConfigurationException("Could not load private Key from Keystore", E);
                }
            }
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
            throw new ConfigurationException("Could not load private Key from Keystore", ex);
        }
    }

    private void applyDHParameters(Config config, DHPublicKeyParameters dhParameters) {
        config.setDefaultDhModulus(dhParameters.getParameters().getP());
        config.setDefaultDhGenerator(dhParameters.getParameters().getG());
        config.setDefaultClientDhPublicKey(dhParameters.getY());
        config.setDefaultServerDhPublicKey(dhParameters.getY());
    }

    private void applyECParameters(Config config, ECPublicKeyParameters ecParameters) {
        config.setDefaultSelectedCurve(CurveNameRetriever.getNamedCuveFromECCurve(ecParameters.getParameters()
                .getCurve()));
        CustomECPoint publicKey = new CustomECPoint(ecParameters.getQ().getRawXCoord().toBigInteger(), ecParameters
                .getQ().getRawYCoord().toBigInteger());
        config.setDefaultClientEcPublicKey(publicKey);
        config.setDefaultServerEcPublicKey(publicKey);
    }

    private void applyRSAParameters(Config config, BigInteger modulus, BigInteger publicKey) {
        config.setDefaultRSAModulus(modulus);
        config.setDefaultClientRSAPublicKey(publicKey);
        config.setDefaultServerRSAPublicKey(publicKey);
    }
}
