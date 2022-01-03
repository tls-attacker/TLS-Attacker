/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.crypto.keys;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Objects;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlAccessorType(XmlAccessType.FIELD)
public class CustomECPrivateKey extends CustomPrivateKey implements ECPrivateKey {

    private static final Logger LOGGER = LogManager.getLogger();

    private final BigInteger privateKey;

    private final NamedGroup group;

    private CustomECPrivateKey() {
        privateKey = null;
        group = null;
    }

    public CustomECPrivateKey(BigInteger privateKey, NamedGroup group) {
        this.privateKey = privateKey;
        this.group = group;
    }

    @Override
    public BigInteger getS() {
        return privateKey;
    }

    @Override
    public String getAlgorithm() {
        return "EC";
    }

    @Override
    public String getFormat() {
        return "None";
    }

    @Override
    public byte[] getEncoded() {
        try {
            ECParameterSpec ecParameters = this.getParams();
            ECPrivateKeySpec privKey = new ECPrivateKeySpec(privateKey, ecParameters);
            PrivateKey privateKey = KeyFactory.getInstance("EC").generatePrivate(privKey);
            return privateKey.getEncoded();
        } catch (InvalidKeySpecException | NoSuchAlgorithmException ex) {
            throw new UnsupportedOperationException("Could not encode the private EC key", ex);
        }
    }

    @Override
    public ECParameterSpec getParams() {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec(group.getJavaName()));
            ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
            return ecParameters;
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException ex) {
            throw new UnsupportedOperationException("Could not generate ECParameterSpec", ex);
        }
    }

    @Override
    public void adjustInContext(TlsContext context, ConnectionEndType ownerOfKey) {
        LOGGER.debug("Adjusting EC private key in context");
        if (null == ownerOfKey) {
            throw new IllegalArgumentException("Owner of Key " + ownerOfKey + " is not supported");
        } else {
            switch (ownerOfKey) {
                case CLIENT:
                    context.setClientEcPrivateKey(privateKey);
                    context.setEcCertificateCurve(group);
                    break;
                case SERVER:
                    context.setServerEcPrivateKey(privateKey);
                    context.setEcCertificateCurve(group);
                    break;
                default:
                    throw new IllegalArgumentException("Owner of Key " + ownerOfKey + " is not supported");
            }
        }
    }

    @Override
    public void adjustInConfig(Config config, ConnectionEndType ownerOfKey) {
        if (null == ownerOfKey) {
            throw new IllegalArgumentException("Owner of Key " + ownerOfKey + " is not supported");
        } else {
            switch (ownerOfKey) {
                case CLIENT:
                    config.setDefaultClientEcPrivateKey(privateKey);
                    config.setDefaultEcCertificateCurve(group);
                    break;
                case SERVER:
                    config.setDefaultServerEcPrivateKey(privateKey);
                    config.setDefaultEcCertificateCurve(group);
                    break;
                default:
                    throw new IllegalArgumentException("Owner of Key " + ownerOfKey + " is not supported");
            }
        }
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 53 * hash + Objects.hashCode(this.privateKey);
        hash = 53 * hash + Objects.hashCode(this.group);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final CustomECPrivateKey other = (CustomECPrivateKey) obj;
        if (!Objects.equals(this.privateKey, other.privateKey)) {
            return false;
        }
        return this.group == other.group;
    }

    @Override
    public String toString() {
        return ArrayConverter.bytesToHexString(privateKey.toByteArray());
    }
}
