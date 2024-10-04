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
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.quic.constants.QuicFrameType;
import de.rub.nds.tlsattacker.core.quic.handler.frame.StopSendingFrameHandler;
import de.rub.nds.tlsattacker.core.quic.parser.frame.StopSendingFrameParser;
import de.rub.nds.tlsattacker.core.quic.preparator.frame.StopSendingFramePreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.frame.StopSendingFrameSerializer;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement
public class StopSendingFrame extends QuicFrame {

    @ModifiableVariableProperty protected ModifiableInteger streamId;

    @ModifiableVariableProperty protected ModifiableInteger applicationProtocolErrorCode;

    private int streamIdConfig;
    private int applicationProtocolErrorCodeConfig;

    public StopSendingFrame() {
        super(QuicFrameType.STOP_SENDING_FRAME);
    }

    public StopSendingFrame(int streamIdConfig, int applicationProtocolErrorCodeConfig) {
        this();
        this.streamIdConfig = streamIdConfig;
        this.applicationProtocolErrorCodeConfig = applicationProtocolErrorCodeConfig;
    }

    @Override
    public StopSendingFrameHandler getHandler(QuicContext context) {
        return new StopSendingFrameHandler(context);
    }

    @Override
    public StopSendingFrameSerializer getSerializer(QuicContext context) {
        return new StopSendingFrameSerializer(this);
    }

    @Override
    public StopSendingFramePreparator getPreparator(QuicContext context) {
        return new StopSendingFramePreparator(context.getChooser(), this);
    }

    @Override
    public StopSendingFrameParser getParser(QuicContext context, InputStream stream) {
        return new StopSendingFrameParser(stream);
    }

    public ModifiableInteger getStreamId() {
        return streamId;
    }

    public void setStreamId(ModifiableInteger streamId) {
        this.streamId = streamId;
    }

    public void setStreamId(int streamId) {
        this.streamId = ModifiableVariableFactory.safelySetValue(this.streamId, streamId);
    }

    public ModifiableInteger getApplicationProtocolErrorCode() {
        return applicationProtocolErrorCode;
    }

    public void setApplicationProtocolErrorCode(ModifiableInteger applicationProtocolErrorCode) {
        this.applicationProtocolErrorCode = applicationProtocolErrorCode;
    }

    public void setApplicationProtocolErrorCode(int applicationProtocolErrorCode) {
        this.applicationProtocolErrorCode =
                ModifiableVariableFactory.safelySetValue(
                        this.applicationProtocolErrorCode, applicationProtocolErrorCode);
    }

    public int getStreamIdConfig() {
        return streamIdConfig;
    }

    public void setStreamIdConfig(int streamIdConfig) {
        this.streamIdConfig = streamIdConfig;
    }

    public int getApplicationProtocolErrorCodeConfig() {
        return applicationProtocolErrorCodeConfig;
    }

    public void setApplicationProtocolErrorCodeConfig(int applicationProtocolErrorCodeConfig) {
        this.applicationProtocolErrorCodeConfig = applicationProtocolErrorCodeConfig;
    }
}
