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
import de.rub.nds.tlsattacker.core.constants.GOSTCurve;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlAccessorType(XmlAccessType.FIELD)
public class CustomEcPublicKey extends CustomPublicKey implements ECPublicKey {

    private final static Logger LOGGER = LogManager.getLogger();

    private final Point point;

    private final NamedGroup group;

    private final GOSTCurve gostCurve;

    private CustomEcPublicKey() {
        this.point = null;
        this.group = null;
        this.gostCurve = null;
    }

    private CustomEcPublicKey(Point point, NamedGroup group) {
        this.point = point;
        this.group = group;
        this.gostCurve = null;
    }

    public CustomEcPublicKey(BigInteger x, BigInteger y, NamedGroup group) {
        this.group = group;
        this.gostCurve = null;
        point = CurveFactory.getCurve(group).getPoint(x, y);
    }

    public CustomEcPublicKey(BigInteger x, BigInteger y, GOSTCurve gostCurve) {
        group = null;
        this.gostCurve = gostCurve;
        point = CurveFactory.getCurve(gostCurve).getPoint(x, y);
    }

    @Override
    public void adjustInContext(TlsContext context, ConnectionEndType ownerOfKey) {
        LOGGER.debug("Adjusting EC public key in context");
        if (null == ownerOfKey) {
            throw new IllegalArgumentException("Owner of Key " + ownerOfKey + " is not supported");
        } else {
            switch (ownerOfKey) {
                case CLIENT:
                    context.setClientEcPublicKey(point);
                    context.setSelectedGroup(group);
                    break;
                case SERVER:
                    context.setServerEcPublicKey(point);
                    context.setSelectedGroup(group);
                    break;
                default:
                    throw new IllegalArgumentException("Owner of Key " + ownerOfKey + " is not supported");
            }
        }
    }

    @Override
    public ECPoint getW() {
        return new ECPoint(point.getX().getData(), point.getY().getData());
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
        if (null == ownerOfKey) {
            throw new IllegalArgumentException("Owner of Key " + ownerOfKey + " is not supported");
        } else {
            switch (ownerOfKey) {
                case CLIENT:
                    config.setDefaultClientEcPublicKey(point);
                    config.setDefaultSelectedNamedGroup(group);
                    break;
                case SERVER:
                    config.setDefaultServerEcPublicKey(point);
                    config.setDefaultSelectedNamedGroup(group);
                    break;
                default:
                    throw new IllegalArgumentException("Owner of Key " + ownerOfKey + " is not supported");
            }
        }
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 79 * hash + Objects.hashCode(this.point);
        hash = 79 * hash + Objects.hashCode(this.group);
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
        if (!Objects.equals(this.point, other.point)) {
            return false;
        }
        if (this.group != other.group) {
            return false;
        }
        return true;
    }
}
