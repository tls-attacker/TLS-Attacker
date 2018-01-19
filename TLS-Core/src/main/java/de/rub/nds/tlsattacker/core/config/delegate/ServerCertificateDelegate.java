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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.crypto.ec.CustomECPoint;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.util.CertificateUtils;
import de.rub.nds.tlsattacker.core.util.CurveNameRetriever;
import de.rub.nds.tlsattacker.core.util.JKSLoader;
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
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.tls.Certificate;

/**
 * This delegate loads a certificate and private key for the server side from a
 * Java Key Store.
 */
public class ServerCertificateDelegate extends Delegate {

    @Parameter(names = "-keystore", description = "Java Key Store (JKS) file to use as server certificate.")
    private String keystore = null;

    @Parameter(names = "-password", description = "Java Key Store (JKS) file password")
    private String password = null;

    @Parameter(names = "-alias", description = "Alias of the key to be used from Java Key Store (JKS)")
    private String alias = null;

    public ServerCertificateDelegate() {
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
                    if (CertificateUtils.hasECParameters(cert)) {
                        ECPublicKeyParameters ecParameters = CertificateUtils.extractECPublicKeyParameters(cert);
                        applyECParameters(config, ecParameters);
                        config.setDefaultServerEcPrivateKey(CertificateUtils.ecPrivateKeyFromPrivateKey(key).getS());
                        config.setDefaultEcCertificate(stream.toByteArray());
                        LOGGER.debug("Loaded EC certificate data:\nmodulus: " + config.getDefaultSelectedCurve()
                                + "\npubkey: " + config.getDefaultServerEcPublicKey() + "\nprivkey: "
                                + config.getDefaultServerEcPrivateKey());
                    } else if (CertificateUtils.hasRSAParameters(cert)) {
                        applyRSAParameters(config, CertificateUtils.extractRSAModulus(cert),
                                CertificateUtils.extractRSAPublicKey(cert));
                        config.setDefaultServerRSAPrivateKey(CertificateUtils.rsaPrivateKeyFromPrivateKey(key)
                                .getPrivateExponent());
                        config.setDefaultRsaCertificate(stream.toByteArray());
                        LOGGER.debug("Loaded RSA certificate data:\nmodulus: " + config.getDefaultServerRSAModulus()
                                + "\npubkey: " + config.getDefaultServerRSAPublicKey() + "\nprivkey: "
                                + config.getDefaultServerRSAPrivateKey());
                    } else {
                        // TODO: DSA
                        throw new UnsupportedOperationException("Certificate type currently not supported");
                    }
                } catch (IOException E) {
                    throw new ConfigurationException("Could not load asymmetric crypto parameters from keystore", E);
                }
            }
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
            throw new ConfigurationException("Could not load certificate or private key from keystore", ex);
        }
    }

    private void applyECParameters(Config config, ECPublicKeyParameters ecParameters) {
        config.setDefaultSelectedCurve(CurveNameRetriever.getNamedCuveFromECCurve(ecParameters.getParameters()
                .getCurve()));
        CustomECPoint publicKey = new CustomECPoint(ecParameters.getQ().getRawXCoord().toBigInteger(), ecParameters
                .getQ().getRawYCoord().toBigInteger());
        config.setDefaultServerEcPublicKey(publicKey);
    }

    private void applyRSAParameters(Config config, BigInteger modulus, BigInteger publicKey) {
        config.setDefaultServerRSAModulus(modulus);
        config.setDefaultServerRSAPublicKey(publicKey);
    }
}
