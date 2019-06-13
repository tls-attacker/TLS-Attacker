/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.ec_;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.workflow.action.ActivateEncryptionAction;
import de.rub.nds.tlsattacker.core.workflow.action.ApplyBufferedMessagesAction;
import de.rub.nds.tlsattacker.core.workflow.action.BufferedGenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.BufferedSendAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeCipherSuiteAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeClientRandomAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeCompressionAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeMasterSecretAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangePreMasterSecretAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeProtocolVersionAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeServerRandomAction;
import de.rub.nds.tlsattacker.core.workflow.action.ClearBuffersAction;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.action.CopyBufferedMessagesAction;
import de.rub.nds.tlsattacker.core.workflow.action.CopyBufferedRecordsAction;
import de.rub.nds.tlsattacker.core.workflow.action.CopyBuffersAction;
import de.rub.nds.tlsattacker.core.workflow.action.CopyClientRandomAction;
import de.rub.nds.tlsattacker.core.workflow.action.CopyContextFieldAction;
import de.rub.nds.tlsattacker.core.workflow.action.CopyPreMasterSecretAction;
import de.rub.nds.tlsattacker.core.workflow.action.CopyServerRandomAction;
import de.rub.nds.tlsattacker.core.workflow.action.DeactivateEncryptionAction;
import de.rub.nds.tlsattacker.core.workflow.action.DeepCopyBufferedMessagesAction;
import de.rub.nds.tlsattacker.core.workflow.action.DeepCopyBufferedRecordsAction;
import de.rub.nds.tlsattacker.core.workflow.action.DeepCopyBuffersAction;
import de.rub.nds.tlsattacker.core.workflow.action.FindReceivedProtocolMessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.FlushSessionCacheAction;
import de.rub.nds.tlsattacker.core.workflow.action.ForwardMessagesAction;
import de.rub.nds.tlsattacker.core.workflow.action.ForwardMessagesWithPrepareAction;
import de.rub.nds.tlsattacker.core.workflow.action.ForwardRecordsAction;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAsciiAction;
import de.rub.nds.tlsattacker.core.workflow.action.MultiReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.PopAndSendAction;
import de.rub.nds.tlsattacker.core.workflow.action.PopAndSendMessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.PopAndSendRecordAction;
import de.rub.nds.tlsattacker.core.workflow.action.PopBufferedMessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.PopBufferedRecordAction;
import de.rub.nds.tlsattacker.core.workflow.action.PopBuffersAction;
import de.rub.nds.tlsattacker.core.workflow.action.PrintLastHandledApplicationDataAction;
import de.rub.nds.tlsattacker.core.workflow.action.PrintProposedExtensionsAction;
import de.rub.nds.tlsattacker.core.workflow.action.PrintSecretsAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAsciiAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.RemBufferedChCiphersAction;
import de.rub.nds.tlsattacker.core.workflow.action.RemBufferedChExtensionsAction;
import de.rub.nds.tlsattacker.core.workflow.action.RenegotiationAction;
import de.rub.nds.tlsattacker.core.workflow.action.ResetConnectionAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAsciiAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicServerKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.action.WaitAction;
import java.io.Serializable;
import java.math.BigInteger;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * Can be used to store a point of an elliptic curve.
 *
 * Affine points store their x and y coordinates. The projective z-coordinate
 * (equal to 1) will not be stored. The point at infinity [0:1:0] (the only
 * point with z-coordinate 0) does not store any of it's coordinates.
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Point implements Serializable {

    /*
     * Point objects are immutable. This should make deep copies in the methods
     * of the EllipticCurve class unnecessary.
     */
    @XmlElements(value = { @XmlElement(type = FieldElementF2m.class, name = "FieldElementF2m"),
            @XmlElement(type = FieldElementFp.class, name = "FieldElementFp") })
    private final FieldElement x;
    @XmlElements(value = { @XmlElement(type = FieldElementF2m.class, name = "FieldElementF2m"),
            @XmlElement(type = FieldElementFp.class, name = "FieldElementFp") })
    private final FieldElement y;
    private final boolean infinity;

    /**
     * Instantiates the point at infinity.
     */
    public Point() {
        this.infinity = true;
        this.x = null;
        this.y = null;
    }

    public static Point createPoint(BigInteger x, BigInteger y, NamedGroup group) {
        EllipticCurve curve = CurveFactory.getCurve(group);
        return curve.getPoint(x, y);
    }

    /**
     * Instantiates an affine point with coordinates x and y. Calling
     * EllipticCurve.getPoint() should always be preferred over using this
     * constructor.
     *
     * @param x
     *            A FieldElement representing the x-coordinate of the point.
     * @param y
     *            A FieldElement representing the y-coordinate of the point. x
     *            and y must be elements of the same field.
     */
    public Point(FieldElement x, FieldElement y) {
        this.x = x;
        this.y = y;
        this.infinity = false;
    }

    /**
     * Returns true if the point is the point at infinity. Returns false if the
     * point is an affine point.
     */
    public boolean isAtInfinity() {
        return this.infinity;
    }

    public FieldElement getX() {
        return this.x;
    }

    public FieldElement getY() {
        return this.y;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null || this.getClass() != obj.getClass()) {
            return false;
        } else {
            Point p = (Point) obj;

            if (this.isAtInfinity() || p.isAtInfinity()) {
                return this.isAtInfinity() == p.isAtInfinity();
            } else {
                return this.x.equals(p.getX()) && this.y.equals(p.getY());
            }
        }
    }

    @Override
    public String toString() {
        if (this.isAtInfinity()) {
            return "Point: Infinity";
        } else {
            return "Point: (" + this.getX().toString() + ", " + this.getY().toString() + ")";
        }
    }
}
