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
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidParameterSpecException;
import java.util.Objects;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

@XmlAccessorType(XmlAccessType.FIELD)
public class CustomEcPublicKey extends CustomPublicKey implements ECPublicKey {

    private final BigInteger x;

    private final BigInteger y;

    private final NamedGroup group;

    private CustomEcPublicKey() {
        x = null;
        y = null;
        group = null;
    }

    public CustomEcPublicKey(BigInteger x, BigInteger y, NamedGroup group) {
        this.x = x;
        this.y = y;
        this.group = group;
    }

    @Override
    public void adjustInContext(TlsContext context, ConnectionEndType ownerOfKey) {
        if (ownerOfKey == ConnectionEndType.CLIENT) {
            context.setClientEcPublicKey(new CustomECPoint(x, y));
            context.setSelectedGroup(group);
        } else if (ownerOfKey == ConnectionEndType.SERVER) {
            context.setServerEcPublicKey(new CustomECPoint(x, y));
            context.setSelectedGroup(group);
        } else {
            throw new IllegalArgumentException("Owner of Key " + ownerOfKey + " is not supported");
        }
    }

    @Override
    public ECPoint getW() {
        return new ECPoint(x, y);
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
        throw new UnsupportedOperationException("Not supported yet.");
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
    public void adjustInConfig(Config config, ConnectionEndType ownerOfKey) {
        if (ownerOfKey == ConnectionEndType.CLIENT) {
            config.setDefaultClientEcPublicKey(new CustomECPoint(x, y));
            config.setDefaultSelectedNamedGroup(group);
        } else if (ownerOfKey == ConnectionEndType.SERVER) {
            config.setDefaultServerEcPublicKey(new CustomECPoint(x, y));
            config.setDefaultSelectedNamedGroup(group);
        } else {
            throw new IllegalArgumentException("Owner of Key " + ownerOfKey + " is not supported");
        }
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 47 * hash + Objects.hashCode(this.x);
        hash = 47 * hash + Objects.hashCode(this.y);
        hash = 47 * hash + Objects.hashCode(this.group);
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
        final CustomEcPublicKey other = (CustomEcPublicKey) obj;
        if (!Objects.equals(this.x, other.x)) {
            return false;
        }
        if (!Objects.equals(this.y, other.y)) {
            return false;
        }
        if (this.group != other.group) {
            return false;
        }
        return true;
    }

}
