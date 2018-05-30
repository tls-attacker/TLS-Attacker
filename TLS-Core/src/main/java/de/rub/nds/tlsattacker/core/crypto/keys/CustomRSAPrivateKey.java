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
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.util.Objects;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

@XmlAccessorType(XmlAccessType.FIELD)
public class CustomRSAPrivateKey extends CustomPrivateKey implements RSAPrivateKey {

    private final BigInteger modulus;
    private final BigInteger privateExponent;

    private CustomRSAPrivateKey() {
        modulus = null;
        privateExponent = null;
    }

    public CustomRSAPrivateKey(BigInteger modulus, BigInteger privateExponent) {
        this.modulus = modulus;
        this.privateExponent = privateExponent;
    }

    @Override
    public BigInteger getPrivateExponent() {
        return privateExponent;
    }

    @Override
    public String getAlgorithm() {
        return "RSA";
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
    public BigInteger getModulus() {
        return modulus;
    }

    @Override
    public void adjustInContext(TlsContext context, ConnectionEndType ownerOfKey) {
        if (ownerOfKey == ConnectionEndType.CLIENT) {
            context.setClientRSAPrivateKey(privateExponent);
            context.setClientRsaModulus(modulus);
        } else if (ownerOfKey == ConnectionEndType.SERVER) {
            context.setServerRSAPrivateKey(privateExponent);
            context.setServerRsaModulus(modulus);
        } else {
            throw new IllegalArgumentException("Owner of Key " + ownerOfKey + " is not supported");
        }
    }

    @Override
    public void adjustInConfig(Config config, ConnectionEndType ownerOfKey) {
        if (ownerOfKey == ConnectionEndType.CLIENT) {
            config.setDefaultClientRSAPrivateKey(privateExponent);
            config.setDefaultClientRSAModulus(modulus);
        } else if (ownerOfKey == ConnectionEndType.SERVER) {
            config.setDefaultServerRSAPrivateKey(privateExponent);
            config.setDefaultServerRSAModulus(modulus);
        } else {
            throw new IllegalArgumentException("Owner of Key " + ownerOfKey + " is not supported");
        }
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 73 * hash + Objects.hashCode(this.modulus);
        hash = 73 * hash + Objects.hashCode(this.privateExponent);
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
        final CustomRSAPrivateKey other = (CustomRSAPrivateKey) obj;
        if (!Objects.equals(this.modulus, other.modulus)) {
            return false;
        }
        if (!Objects.equals(this.privateExponent, other.privateExponent)) {
            return false;
        }
        return true;
    }
}
