/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto.keys;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.spec.DSAParameterSpec;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlAccessorType(XmlAccessType.FIELD)
public class CustomDSAPrivateKey extends CustomPrivateKey implements DSAPrivateKey {

    private static final Logger LOGGER = LogManager.getLogger();

    private final BigInteger privateKey;

    private final BigInteger primeP;
    private final BigInteger primeQ;
    private final BigInteger generator;

    public CustomDSAPrivateKey(
            BigInteger privateKey, BigInteger primeP, BigInteger primeQ, BigInteger generator) {
        this.privateKey = privateKey;
        this.primeP = primeP;
        this.primeQ = primeQ;
        this.generator = generator;
    }

    private CustomDSAPrivateKey() {
        primeP = null;
        primeQ = null;
        generator = null;
        privateKey = null;
    }

    @Override
    public BigInteger getX() {
        return privateKey;
    }

    @Override
    public DSAParams getParams() {
        return new DSAParameterSpec(primeP, primeQ, generator);
    }

    @Override
    public String getAlgorithm() {
        return "DSA";
    }

    @Override
    public String getFormat() {
        return "DSA";
    }

    @Override
    public byte[] getEncoded() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void adjustInContext(TlsContext tlsContext, ConnectionEndType ownerOfKey) {
        LOGGER.debug("Adjusting DSA private key in context");
        if (null == ownerOfKey) {
            throw new IllegalArgumentException("Owner of Key " + ownerOfKey + " is not supported");
        } else {
            switch (ownerOfKey) {
                case CLIENT:
                    tlsContext.setClientDsaPrivateKey(privateKey);
                    tlsContext.setClientDsaGenerator(generator);
                    tlsContext.setClientDsaPrimeP(primeP);
                    tlsContext.setClientDsaPrimeQ(primeQ);
                    break;
                case SERVER:
                    tlsContext.setServerDsaPrivateKey(privateKey);
                    tlsContext.setServerDsaGenerator(generator);
                    tlsContext.setServerDsaPrimeP(primeP);
                    tlsContext.setServerDsaPrimeQ(primeQ);
                    break;
                default:
                    throw new IllegalArgumentException(
                            "Owner of Key " + ownerOfKey + " is not supported");
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
                    config.setDefaultClientDsaPrivateKey(privateKey);
                    config.setDefaultClientDsaPrimeP(primeP);
                    config.setDefaultClientDsaPrimeQ(primeQ);
                    config.setDefaultClientDsaGenerator(generator);
                    break;
                case SERVER:
                    config.setDefaultServerDsaPrivateKey(privateKey);
                    config.setDefaultServerDsaPrimeP(primeP);
                    config.setDefaultServerDsaPrimeQ(primeQ);
                    config.setDefaultServerDsaGenerator(generator);
                    break;
                default:
                    throw new IllegalArgumentException(
                            "Owner of Key " + ownerOfKey + " is not supported");
            }
        }
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 53 * hash + Objects.hashCode(this.privateKey);
        hash = 53 * hash + Objects.hashCode(this.primeP);
        hash = 53 * hash + Objects.hashCode(this.primeQ);
        hash = 53 * hash + Objects.hashCode(this.generator);
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
        final CustomDSAPrivateKey other = (CustomDSAPrivateKey) obj;
        if (!Objects.equals(this.privateKey, other.privateKey)) {
            return false;
        }
        if (!Objects.equals(this.primeP, other.primeP)) {
            return false;
        }
        if (!Objects.equals(this.primeQ, other.primeQ)) {
            return false;
        }
        return Objects.equals(this.generator, other.generator);
    }
}
