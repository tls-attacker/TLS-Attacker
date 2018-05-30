/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.keys;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.CustomECPoint;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Objects;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

@XmlAccessorType(XmlAccessType.FIELD)
public class CustomECPrivateKey extends CustomPrivateKey implements ECPrivateKey {

    private final BigInteger privatekey;

    private final NamedGroup group;

    private CustomECPrivateKey() {
        privatekey = null;
        group = null;
    }

    public CustomECPrivateKey(BigInteger privatekey, NamedGroup group) {
        this.privatekey = privatekey;
        this.group = group;
    }

    @Override
    public BigInteger getS() {
        return privatekey;
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
        throw new UnsupportedOperationException("CustomKey cannot be encoded");
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
        if (ownerOfKey == ConnectionEndType.CLIENT) {
            context.setClientEcPrivateKey(privatekey);
            context.setSelectedGroup(group);
        } else if (ownerOfKey == ConnectionEndType.SERVER) {
            context.setServerEcPrivateKey(privatekey);
            context.setSelectedGroup(group);
        } else {
            throw new IllegalArgumentException("Owner of Key " + ownerOfKey + " is not supported");
        }
    }

    @Override
    public void adjustInConfig(Config config, ConnectionEndType ownerOfKey) {
        if (ownerOfKey == ConnectionEndType.CLIENT) {
            config.setDefaultClientEcPrivateKey(privatekey);
            config.setDefaultSelectedNamedGroup(group);
        } else if (ownerOfKey == ConnectionEndType.SERVER) {
            config.setDefaultServerEcPrivateKey(privatekey);
            config.setDefaultSelectedNamedGroup(group);
        } else {
            throw new IllegalArgumentException("Owner of Key " + ownerOfKey + " is not supported");
        }
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 53 * hash + Objects.hashCode(this.privatekey);
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
        if (!Objects.equals(this.privatekey, other.privatekey)) {
            return false;
        }
        if (this.group != other.group) {
            return false;
        }
        return true;
    }
}
