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
import de.rub.nds.modifiablevariable.longint.ModifiableLong;
import de.rub.nds.tlsattacker.core.quic.constants.QuicFrameType;
import de.rub.nds.tlsattacker.core.quic.handler.frame.AckFrameHandler;
import de.rub.nds.tlsattacker.core.quic.parser.frame.AckFrameParser;
import de.rub.nds.tlsattacker.core.quic.preparator.frame.AckFramePreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.frame.AckFrameSerializer;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/**
 * Receivers send ACK frames (types 0x02 and 0x03) to inform senders of packets they have received
 * and processed. The ACK frame contains one or more ACK Ranges. ACK Ranges identify acknowledged
 * packets. If the frame type is 0x03, ACK frames also contain the cumulative count of QUIC packets
 * with associated ECN marks received on the connection up until this point.
 */
@XmlRootElement
public class AckFrame extends QuicFrame {

    @ModifiableVariableProperty protected ModifiableLong largestAcknowledged;

    @ModifiableVariableProperty protected ModifiableLong ackDelay;

    @ModifiableVariableProperty protected ModifiableLong ackRangeCount;

    @ModifiableVariableProperty protected ModifiableLong firstACKRange;

    @ModifiableVariableProperty protected ModifiableLong packetNumberSpace;

    public AckFrame() {
        super(QuicFrameType.ACK_FRAME);
    }

    protected AckFrame(QuicFrameType frameType) {
        super(frameType);
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

    public void setAckDelay(long ackDelay) {
        this.ackDelay = ModifiableVariableFactory.safelySetValue(this.ackDelay, ackDelay);
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

    public void setAckRangeCount(long ackRangeCount) {
        this.ackRangeCount =
                ModifiableVariableFactory.safelySetValue(this.ackRangeCount, ackRangeCount);
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
}
