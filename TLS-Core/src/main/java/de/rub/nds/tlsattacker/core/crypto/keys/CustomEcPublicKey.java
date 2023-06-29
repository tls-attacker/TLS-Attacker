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
import de.rub.nds.tlsattacker.core.constants.GOSTCurve;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlAccessorType(XmlAccessType.FIELD)
public class CustomEcPublicKey extends CustomPublicKey implements ECPublicKey {

    private static final Logger LOGGER = LogManager.getLogger();

    private Point point;

    private NamedGroup group;

    private GOSTCurve gostCurve;

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

    public Point getPoint() {
        return point;
    }

    public NamedGroup getGroup() {
        return group;
    }

    public GOSTCurve getGostCurve() {
        return gostCurve;
    }

    @Override
    public void adjustInContext(TlsContext tlsContext, ConnectionEndType ownerOfKey) {
        LOGGER.debug("Adjusting EC public key in context");
        if (null == ownerOfKey) {
            throw new IllegalArgumentException("Owner of Key " + ownerOfKey + " is not supported");
        } else {
            switch (ownerOfKey) {
                case CLIENT:
                    tlsContext.setClientEcPublicKey(point);
                    if (group != null) {
                        tlsContext.setEcCertificateCurve(group);
                    }
                    break;
                case SERVER:
                    tlsContext.setServerEcPublicKey(point);
                    if (group != null) {
                        tlsContext.setEcCertificateCurve(group);
                    }
                    break;
                default:
                    throw new IllegalArgumentException(
                            "Owner of Key " + ownerOfKey + " is not supported");
            }
        }
    }

    @Override
    public ECPoint getW() {
        return new ECPoint(point.getFieldX().getData(), point.getFieldY().getData());
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
            ECPublicKeySpec pubKey = new ECPublicKeySpec(getW(), ecParameters);
            PublicKey publicKey = KeyFactory.getInstance("EC").generatePublic(pubKey);
            return publicKey.getEncoded();
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
    public void adjustInConfig(Config config, ConnectionEndType ownerOfKey) {
        if (null == ownerOfKey) {
            throw new IllegalArgumentException("Owner of Key " + ownerOfKey + " is not supported");
        } else {
            switch (ownerOfKey) {
                case CLIENT:
                    config.setDefaultClientEcPublicKey(point);
                    if (group != null) {
                        config.setDefaultEcCertificateCurve(group);
                    }
                    break;
                case SERVER:
                    config.setDefaultServerEcPublicKey(point);
                    if (group != null) {
                        config.setDefaultEcCertificateCurve(group);
                    }
                    break;
                default:
                    throw new IllegalArgumentException(
                            "Owner of Key " + ownerOfKey + " is not supported");
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

    public void setPoint(Point point) {
        this.point = point;
    }

    public void setGroup(NamedGroup group) {
        this.group = group;
    }

    public void setGostCurve(GOSTCurve gostCurve) {
        this.gostCurve = gostCurve;
    }

    @Override
    public int keySize() {
        if (group == null || group.getCoordinateSizeInBit() == null) {
            return 0;
        }
        return group.getCoordinateSizeInBit();
    }
}
