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
import de.rub.nds.tlsattacker.core.crypto.ec.CustomECPoint;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.math.BigInteger;
import java.util.Objects;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

@XmlAccessorType(XmlAccessType.FIELD)
public class CustomDHPrivateKey extends CustomPrivateKey implements DHPrivateKey {

    private final BigInteger privateKey;
    private final BigInteger modulus;
    private final BigInteger generator;

    private CustomDHPrivateKey() {
        privateKey = null;
        modulus = null;
        generator = null;
    }

    public CustomDHPrivateKey(BigInteger privateKey, BigInteger modulus, BigInteger generator) {
        this.privateKey = privateKey;
        this.modulus = modulus;
        this.generator = generator;
    }

    @Override
    public BigInteger getX() {
        return privateKey;
    }

    @Override
    public DHParameterSpec getParams() {
        return new DHParameterSpec(modulus, generator);
    }

    @Override
    public String getAlgorithm() {
        return "DH";
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
    public void adjustInContext(TlsContext context, ConnectionEndType ownerOfKey) {
        if (ownerOfKey == ConnectionEndType.CLIENT) {
            context.setClientDhPrivateKey(privateKey);
        } else if (ownerOfKey == ConnectionEndType.SERVER) {
            context.setServerDhPrivateKey(privateKey);
        } else {
            throw new IllegalArgumentException("Owner of Key " + ownerOfKey + " is not supported");
        }
    }

    @Override
    public void adjustInConfig(Config config, ConnectionEndType ownerOfKey) {
        if (ownerOfKey == ConnectionEndType.CLIENT) {
            config.setDefaultClientDhPrivateKey(privateKey);
        } else if (ownerOfKey == ConnectionEndType.SERVER) {
            config.setDefaultServerDhPrivateKey(privateKey);
        } else {
            throw new IllegalArgumentException("Owner of Key " + ownerOfKey + " is not supported");
        }
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 23 * hash + Objects.hashCode(this.privateKey);
        hash = 23 * hash + Objects.hashCode(this.modulus);
        hash = 23 * hash + Objects.hashCode(this.generator);
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
        final CustomDHPrivateKey other = (CustomDHPrivateKey) obj;
        if (!Objects.equals(this.privateKey, other.privateKey)) {
            return false;
        }
        if (!Objects.equals(this.modulus, other.modulus)) {
            return false;
        }
        if (!Objects.equals(this.generator, other.generator)) {
            return false;
        }
        return true;
    }
}
