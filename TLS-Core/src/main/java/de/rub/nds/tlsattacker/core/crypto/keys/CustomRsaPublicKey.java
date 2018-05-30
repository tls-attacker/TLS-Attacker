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
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

@XmlAccessorType(XmlAccessType.FIELD)
public class CustomRsaPublicKey extends CustomPublicKey implements RSAPublicKey {

    private final BigInteger publicExponent;

    private final BigInteger modulus;

    private CustomRsaPublicKey() {
        publicExponent = null;
        modulus = null;
    }

    public CustomRsaPublicKey(BigInteger publicExponent, BigInteger modulus) {
        this.publicExponent = publicExponent;
        this.modulus = modulus;
    }

    @Override
    public void adjustInContext(TlsContext context, ConnectionEndType ownerOfKey) {
        if (ownerOfKey == ConnectionEndType.CLIENT) {
            context.setClientRSAPublicKey(publicExponent);
            context.setClientRsaModulus(modulus);
        } else if (ownerOfKey == ConnectionEndType.SERVER) {
            context.setServerRSAPublicKey(publicExponent);
            context.setServerRsaModulus(modulus);
        } else {
            throw new IllegalArgumentException("Owner of Key " + ownerOfKey + " is not supported");
        }
    }

    @Override
    public BigInteger getPublicExponent() {
        return publicExponent;
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
        throw new UnsupportedOperationException("Not supported yet."); // To
        // change
        // body
        // of
        // generated
        // methods,
        // choose
        // Tools
        // |
        // Templates.
    }

    @Override
    public BigInteger getModulus() {
        return modulus;
    }

    @Override
    public void adjustInConfig(Config config, ConnectionEndType ownerOfKey) {
        if (ownerOfKey == ConnectionEndType.CLIENT) {
            config.setDefaultClientRSAPublicKey(publicExponent);
            config.setDefaultClientRSAModulus(modulus);
        } else if (ownerOfKey == ConnectionEndType.SERVER) {
            config.setDefaultServerRSAPublicKey(publicExponent);
            config.setDefaultServerRSAModulus(modulus);
        } else {
            throw new IllegalArgumentException("Owner of Key " + ownerOfKey + " is not supported");
        }
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 23 * hash + Objects.hashCode(this.publicExponent);
        hash = 23 * hash + Objects.hashCode(this.modulus);
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
        final CustomRsaPublicKey other = (CustomRsaPublicKey) obj;
        if (!Objects.equals(this.publicExponent, other.publicExponent)) {
            return false;
        }
        if (!Objects.equals(this.modulus, other.modulus)) {
            return false;
        }
        return true;
    }
}
