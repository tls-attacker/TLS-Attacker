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
import de.rub.nds.tlsattacker.core.quic.handler.frame.ResetStreamFrameHandler;
import de.rub.nds.tlsattacker.core.quic.parser.frame.ResetStreamFrameParser;
import de.rub.nds.tlsattacker.core.quic.preparator.frame.ResetStreamFramePreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.frame.ResetStreamFrameSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement
public class ResetStreamFrame extends QuicFrame {

    @ModifiableVariableProperty protected ModifiableInteger streamId;

    @ModifiableVariableProperty protected ModifiableInteger applicationProtocolErrorCode;

    @ModifiableVariableProperty protected ModifiableInteger finalSize;

    private int streamIdConfig;
    private int applicationProtocolErrorCodeConfig;
    private int finalSizeConfig;

    public ResetStreamFrame() {
        super(QuicFrameType.RESET_STREAM_FRAME);
    }

    public ResetStreamFrame(
            int streamIdConfig, int applicationProtocolErrorCodeConfig, int finalSizeConfig) {
        this();
        this.streamIdConfig = streamIdConfig;
        this.applicationProtocolErrorCodeConfig = applicationProtocolErrorCodeConfig;
        this.finalSizeConfig = finalSizeConfig;
    }

    @Override
    public ResetStreamFrameHandler getHandler(Context context) {
        return new ResetStreamFrameHandler(context.getQuicContext());
    }

    @Override
    public ResetStreamFrameSerializer getSerializer(Context context) {
        return new ResetStreamFrameSerializer(this);
    }

    @Override
    public ResetStreamFramePreparator getPreparator(Context context) {
        return new ResetStreamFramePreparator(context.getChooser(), this);
    }

    @Override
    public ResetStreamFrameParser getParser(Context context, InputStream stream) {
        return new ResetStreamFrameParser(stream);
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

    public ModifiableInteger getFinalSize() {
        return finalSize;
    }

    public void setFinalSize(ModifiableInteger finalSize) {
        this.finalSize = finalSize;
    }

    public void setFinalSize(int finalSize) {
        this.finalSize = ModifiableVariableFactory.safelySetValue(this.finalSize, finalSize);
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

    public int getFinalSizeConfig() {
        return finalSizeConfig;
    }

    public void setFinalSizeConfig(int finalSizeConfig) {
        this.finalSizeConfig = finalSizeConfig;
    }
}
