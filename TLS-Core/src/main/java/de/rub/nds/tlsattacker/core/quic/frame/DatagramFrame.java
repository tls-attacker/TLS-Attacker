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
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.quic.constants.QuicFrameType;
import de.rub.nds.tlsattacker.core.quic.handler.frame.DatagramFrameHandler;
import de.rub.nds.tlsattacker.core.quic.parser.frame.DatagramFrameParser;
import de.rub.nds.tlsattacker.core.quic.preparator.frame.DatagramFramePreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.frame.DatagramFrameSerializer;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement
public class DatagramFrame extends QuicFrame {

    @ModifiableVariableProperty protected ModifiableInteger length;

    @ModifiableVariableProperty protected ModifiableByteArray data;

    private int lengthConfig;
    private byte[] dataConfig;

    @SuppressWarnings("unused") // JAXB
    private DatagramFrame() {}

    public DatagramFrame(boolean isLengthField) {
        if (isLengthField) {
            setFrameType(QuicFrameType.DATAGRAM_FRAME_LEN);
        } else {
            setFrameType(QuicFrameType.DATAGRAM_FRAME);
        }
        ackEliciting = false;
    }

    public DatagramFrame(boolean isBidirectional, int length, byte[] dataConfig) {
        this(isBidirectional);
        this.lengthConfig = dataConfig.length;
        this.dataConfig = dataConfig;
    }

    @Override
    public DatagramFrameHandler getHandler(QuicContext context) {
        return new DatagramFrameHandler(context);
    }

    @Override
    public DatagramFrameSerializer getSerializer(QuicContext context) {
        return new DatagramFrameSerializer(this);
    }

    @Override
    public DatagramFramePreparator getPreparator(QuicContext context) {
        return new DatagramFramePreparator(context.getChooser(), this);
    }

    @Override
    public DatagramFrameParser getParser(QuicContext context, InputStream stream) {
        return new DatagramFrameParser(stream);
    }

    public ModifiableInteger getLength() {
        return length;
    }

    public void setLength(ModifiableInteger length) {
        this.length = length;
    }

    public void setLength(int length) {
        this.length = ModifiableVariableFactory.safelySetValue(this.length, length);
    }

    public ModifiableByteArray getData() {
        return data;
    }

    public void setData(ModifiableByteArray data) {
        this.data = data;
    }

    public void setData(byte[] data) {
        this.data = ModifiableVariableFactory.safelySetValue(this.data, data);
    }

    public int getLengthConfig() {
        return lengthConfig;
    }

    public void setLengthConfig(int lengthConfig) {
        this.lengthConfig = lengthConfig;
    }

    public byte[] getDataConfig() {
        return dataConfig;
    }

    public void setDataConfig(byte[] dataConfig) {
        this.dataConfig = dataConfig;
    }
}
