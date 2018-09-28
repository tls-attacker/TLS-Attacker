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
import java.util.Objects;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlAccessorType(XmlAccessType.FIELD)
public class CustomDhPublicKey extends CustomPublicKey implements DHPublicKey {

    private final static Logger LOGGER = LogManager.getLogger();

    private final BigInteger modulus;

    private final BigInteger generator;

    private final BigInteger publicKey;

    public CustomDhPublicKey(BigInteger modulus, BigInteger generator, BigInteger publicKey) {
        this.modulus = modulus;
        this.generator = generator;
        this.publicKey = publicKey;
    }

    private CustomDhPublicKey() {
        modulus = null;
        generator = null;
        publicKey = null;
    }

    @Override
    public void adjustInContext(TlsContext context, ConnectionEndType ownerOfKey) {
        LOGGER.debug("Adjusting DH public key in context");
        if (null == ownerOfKey) {
            throw new IllegalArgumentException("Owner of Key " + ownerOfKey + " is not supported");
        } else {
            switch (ownerOfKey) {
                case CLIENT:
                    context.setClientDhGenerator(generator);
                    context.setClientDhModulus(modulus);
                    context.setClientDhPublicKey(publicKey);
                    break;
                case SERVER:
                    context.setServerDhGenerator(generator);
                    context.setServerDhModulus(modulus);
                    context.setServerDhPublicKey(publicKey);
                    break;
                default:
                    throw new IllegalArgumentException("Owner of Key " + ownerOfKey + " is not supported");
            }
        }
    }

    @Override
    public BigInteger getY() {
        return publicKey;
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
        throw new UnsupportedOperationException("Not supported yet."); // To
    }

    @Override
    public void adjustInConfig(Config config, ConnectionEndType ownerOfKey) {
        if (null == ownerOfKey) {
            throw new IllegalArgumentException("Owner of Key " + ownerOfKey + " is not supported");
        } else {
            switch (ownerOfKey) {
                case CLIENT:
                    config.setDefaultClientDhGenerator(generator);
                    config.setDefaultClientDhModulus(modulus);
                    config.setDefaultClientDhPublicKey(publicKey);
                    break;
                case SERVER:
                    config.setDefaultServerDhGenerator(generator);
                    config.setDefaultServerDhModulus(modulus);
                    config.setDefaultServerDhPublicKey(publicKey);
                    break;
                default:
                    throw new IllegalArgumentException("Owner of Key " + ownerOfKey + " is not supported");
            }
        }
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 79 * hash + Objects.hashCode(this.modulus);
        hash = 79 * hash + Objects.hashCode(this.generator);
        hash = 79 * hash + Objects.hashCode(this.publicKey);
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
        final CustomDhPublicKey other = (CustomDhPublicKey) obj;
        if (!Objects.equals(this.modulus, other.modulus)) {
            return false;
        }
        if (!Objects.equals(this.generator, other.generator)) {
            return false;
        }
        return Objects.equals(this.publicKey, other.publicKey);
    }
}
