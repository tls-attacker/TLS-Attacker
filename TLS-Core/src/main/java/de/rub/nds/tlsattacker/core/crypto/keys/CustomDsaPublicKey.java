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
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAParameterSpec;
import java.util.Objects;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlAccessorType(XmlAccessType.FIELD)
public class CustomDsaPublicKey extends CustomPublicKey implements DSAPublicKey {

    private final static Logger LOGGER = LogManager.getLogger();

    private final BigInteger p;
    private final BigInteger q;
    private final BigInteger g;

    private final BigInteger publicKey;

    public CustomDsaPublicKey(BigInteger p, BigInteger q, BigInteger g, BigInteger publicKey) {
        this.p = p;
        this.q = q;
        this.g = g;
        this.publicKey = publicKey;
    }

    private CustomDsaPublicKey() {
        p = null;
        q = null;
        g = null;
        publicKey = null;
    }

    @Override
    public void adjustInContext(TlsContext context, ConnectionEndType ownerOfKey) {
        LOGGER.debug("Adjusting DSA public key in context");
        if (null == ownerOfKey) {
            throw new IllegalArgumentException("Owner of Key " + ownerOfKey + " is not supported");
        } else
            switch (ownerOfKey) {
                case CLIENT:
                    context.setClientDsaGenerator(g);
                    context.setClientDsaPrimeP(p);
                    context.setClientDsaPrimeQ(q);
                    context.setClientDsaPublicKey(publicKey);
                    break;
                case SERVER:
                    context.setServerDsaGenerator(g);
                    context.setServerDsaPrimeP(p);
                    context.setServerDsaPrimeQ(q);
                    context.setServerDsaPublicKey(publicKey);
                    break;
                default:
                    throw new IllegalArgumentException("Owner of Key " + ownerOfKey + " is not supported");
            }
    }

    @Override
    public BigInteger getY() {
        return publicKey;
    }

    @Override
    public DSAParams getParams() {
        return new DSAParameterSpec(p, q, g);
    }

    @Override
    public String getAlgorithm() {
        return "DSA";
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
        } else
            switch (ownerOfKey) {
                case CLIENT:
                    config.setDefaultClientDsaGenerator(g);
                    config.setDefaultClientDsaPrimeP(p);
                    config.setDefaultClientDsaPrimeQ(q);
                    config.setDefaultClientDsaPublicKey(publicKey);
                    break;
                case SERVER:
                    config.setDefaultServerDsaGenerator(g);
                    config.setDefaultServerDsaPrimeP(p);
                    config.setDefaultServerDsaPrimeQ(q);
                    config.setDefaultServerDsaPublicKey(publicKey);
                    break;
                default:
                    throw new IllegalArgumentException("Owner of Key " + ownerOfKey + " is not supported");
            }
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 59 * hash + Objects.hashCode(this.p);
        hash = 59 * hash + Objects.hashCode(this.q);
        hash = 59 * hash + Objects.hashCode(this.g);
        hash = 59 * hash + Objects.hashCode(this.publicKey);
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
        final CustomDsaPublicKey other = (CustomDsaPublicKey) obj;
        if (!Objects.equals(this.p, other.p)) {
            return false;
        }
        if (!Objects.equals(this.q, other.q)) {
            return false;
        }
        if (!Objects.equals(this.g, other.g)) {
            return false;
        }
        return Objects.equals(this.publicKey, other.publicKey);
    }
}
