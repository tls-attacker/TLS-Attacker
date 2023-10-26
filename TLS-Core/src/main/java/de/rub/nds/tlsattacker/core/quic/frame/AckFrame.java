/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.frame;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.mlong.ModifiableLong;
import de.rub.nds.tlsattacker.core.quic.constants.QuicFrameType;
import de.rub.nds.tlsattacker.core.quic.handler.frame.AckFrameHandler;
import de.rub.nds.tlsattacker.core.quic.parser.frame.AckFrameParser;
import de.rub.nds.tlsattacker.core.quic.preparator.frame.AckFramePreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.frame.AckFrameSerializer;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement
public class AckFrame extends QuicFrame<AckFrame> {

    /**
     * A variable-length integer representing the largest packet number the peer is acknowledging;
     * this is usually the largest packet number that the peer has received prior to generating the
     * ACK frame. Unlike the packet number in the QUIC long or short header, the value in an ACK
     * frame is not truncated.
     */
    @ModifiableVariableProperty protected ModifiableLong largestAcknowledged;

    /**
     * A variable-length integer encoding the acknowledgment delay in microseconds; see Section
     * 13.2.5. It is decoded by multiplying the value in the field by 2 to the power of the
     * ack_delay_exponent transport parameter sent by the sender of the ACK frame; see Section 18.2.
     * Compared to simply expressing the delay as an integer, this encoding allows for a larger
     * range of values within the same number of bytes, at the cost of lower resolution.
     */
    @ModifiableVariableProperty protected ModifiableLong ackDelay;

    /** A variable-length integer specifying the number of ACK Range fields in the frame. */
    @ModifiableVariableProperty protected ModifiableLong ackRangeCount;

    /**
     * A variable-length integer indicating the number of contiguous packets preceding the Largest
     * Acknowledged that are being acknowledged. That is, the smallest packet acknowledged in the
     * range is determined by subtracting the First ACK Range value from the Largest Acknowledged
     * field.
     */
    @ModifiableVariableProperty protected ModifiableLong firstACKRange;

    /**
     * Contains additional ranges of packets that are alternately not acknowledged (Gap) and
     * acknowledged (ACK Range); see Section 19.3.1.
     */
    @ModifiableVariableProperty protected ModifiableLong packetNumberSpace;

    public AckFrame() {
        super(QuicFrameType.ACK_FRAME);
    }

    public void setLargestAcknowledged(ModifiableLong largestAcknowledged) {
        this.largestAcknowledged = largestAcknowledged;
    }

    public void setLargestAcknowledged(int largestAcknowledged) {
        this.largestAcknowledged =
                ModifiableVariableFactory.safelySetValue(
                        this.largestAcknowledged, (long) largestAcknowledged);
    }

    public void setLargestAcknowledged(long largestAcknowledged) {
        this.largestAcknowledged =
                ModifiableVariableFactory.safelySetValue(
                        this.largestAcknowledged, largestAcknowledged);
    }

    public ModifiableLong getLargestAcknowledged() {
        return largestAcknowledged;
    }

    public void setAckDelay(ModifiableLong ackDelay) {
        this.ackDelay = ackDelay;
    }

    public void setAckDelay(int ackDelay) {
        this.ackDelay = ModifiableVariableFactory.safelySetValue(this.ackDelay, (long) ackDelay);
    }

    public ModifiableLong getAckDelay() {
        return ackDelay;
    }

    public void setAckRangeCount(ModifiableLong ackRangeCount) {
        this.ackRangeCount = ackRangeCount;
    }

    public void setAckRangeCount(int ackRangeCount) {
        this.ackRangeCount =
                ModifiableVariableFactory.safelySetValue(this.ackRangeCount, (long) ackRangeCount);
    }

    public ModifiableLong getAckRangeCount() {
        return ackRangeCount;
    }

    public void setFirstACKRange(ModifiableLong firstACKRange) {
        this.firstACKRange = firstACKRange;
    }

    public void setFirstACKRange(long firstACKRange) {
        this.firstACKRange =
                ModifiableVariableFactory.safelySetValue(this.firstACKRange, firstACKRange);
    }

    public void setFirstACKRange(int firstACKRange) {
        this.firstACKRange =
                ModifiableVariableFactory.safelySetValue(this.firstACKRange, (long) firstACKRange);
    }

    public ModifiableLong getFirstACKRange() {
        return firstACKRange;
    }

    public void setPacketNumberSpace(ModifiableLong packetNumberSpace) {
        this.packetNumberSpace = packetNumberSpace;
    }

    public void setPacketNumberSpace(long packetNumberSpace) {
        this.packetNumberSpace =
                ModifiableVariableFactory.safelySetValue(this.packetNumberSpace, packetNumberSpace);
    }

    public void setPacketNumberSpace(int packetNumberSpace) {
        this.packetNumberSpace =
                ModifiableVariableFactory.safelySetValue(
                        this.packetNumberSpace, (long) packetNumberSpace);
    }

    public ModifiableLong getPacketNumberSpace() {
        return packetNumberSpace;
    }

    @Override
    public AckFrameHandler getHandler(QuicContext context) {
        return new AckFrameHandler(context);
    }

    @Override
    public AckFrameSerializer getSerializer(QuicContext context) {
        return new AckFrameSerializer(this);
    }

    @Override
    public AckFramePreparator getPreparator(QuicContext context) {
        return new AckFramePreparator(context.getChooser(), this);
    }

    @Override
    public AckFrameParser getParser(QuicContext context, InputStream stream) {
        return new AckFrameParser(stream);
    }
}
