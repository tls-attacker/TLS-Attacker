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
import de.rub.nds.modifiablevariable.longint.ModifiableLong;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.quic.constants.QuicFrameType;
import de.rub.nds.tlsattacker.core.quic.constants.QuicTransportErrorCodes;
import de.rub.nds.tlsattacker.core.quic.handler.frame.ConnectionCloseFrameHandler;
import de.rub.nds.tlsattacker.core.quic.parser.frame.ConnectionCloseFrameParser;
import de.rub.nds.tlsattacker.core.quic.preparator.frame.ConnectionCloseFramePreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.frame.ConnectionCloseFrameSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * An endpoint sends a CONNECTION_CLOSE frame (type=0x1c or 0x1d) to notify its peer that the
 * connection is being closed.
 */
@XmlRootElement
public class ConnectionCloseFrame extends QuicFrame {

    @ModifiableVariableProperty private ModifiableLong errorCode;

    @ModifiableVariableProperty private ModifiableLong triggerFrameType;

    @ModifiableVariableProperty private ModifiableLong reasonPhraseLength;

    @ModifiableVariableProperty private ModifiableByteArray reasonPhrase;

    private long errorCodeConfig;
    private long triggerFrameTypeConfig;
    private long reasonPhraseLengthConfig;
    private byte[] reasonPhraseConfig;

    @SuppressWarnings("unused") // JAXB
    private ConnectionCloseFrame() {}

    public ConnectionCloseFrame(boolean isQuicLayer) {
        if (isQuicLayer) {
            setFrameType(QuicFrameType.CONNECTION_CLOSE_QUIC_FRAME);
        } else {
            setFrameType(QuicFrameType.CONNECTION_CLOSE_APPLICATION_FRAME);
        }
        ackEliciting = false;
    }

    public ConnectionCloseFrame(long errorCodeConfig) {
        this(true);
        this.errorCodeConfig = errorCodeConfig;
    }

    public ConnectionCloseFrame(int errorCodeConfig, String reasonPhraseConfig) {
        this(errorCodeConfig);
        this.reasonPhraseConfig = reasonPhraseConfig.getBytes(StandardCharsets.UTF_8);
        this.reasonPhraseLengthConfig = this.reasonPhraseConfig.length;
    }

    public ConnectionCloseFrame(
            int errorCodeConfig, long triggerFrameTypeConfig, String reasonPhraseConfig) {
        this(errorCodeConfig);
        this.reasonPhraseConfig = reasonPhraseConfig.getBytes(StandardCharsets.UTF_8);
        this.reasonPhraseLengthConfig = this.reasonPhraseConfig.length;
        this.triggerFrameTypeConfig = triggerFrameTypeConfig;
    }

    @Override
    public ConnectionCloseFrameHandler getHandler(Context context) {
        return new ConnectionCloseFrameHandler(context.getQuicContext());
    }

    @Override
    public ConnectionCloseFrameSerializer getSerializer(Context context) {
        return new ConnectionCloseFrameSerializer(this);
    }

    @Override
    public ConnectionCloseFramePreparator getPreparator(Context context) {
        return new ConnectionCloseFramePreparator(context.getChooser(), this);
    }

    @Override
    public ConnectionCloseFrameParser getParser(Context context, InputStream stream) {
        return new ConnectionCloseFrameParser(stream);
    }

    public ModifiableLong getErrorCode() {
        return errorCode;
    }

    public void setErrorCode(long errorCode) {
        this.errorCode = ModifiableVariableFactory.safelySetValue(this.errorCode, errorCode);
    }

    public void setErrorCode(int errorCode) {
        this.setErrorCode((long) errorCode);
    }

    public ModifiableLong getTriggerFrameType() {
        return triggerFrameType;
    }

    public void setTriggerFrameType(long triggerFrameType) {
        this.triggerFrameType =
                ModifiableVariableFactory.safelySetValue(this.triggerFrameType, triggerFrameType);
    }

    public void setTriggerFrameType(int triggerFrameType) {
        this.setTriggerFrameType((long) triggerFrameType);
    }

    public ModifiableLong getReasonPhraseLength() {
        return reasonPhraseLength;
    }

    public void setReasonPhraseLength(long reasonPhraseLength) {
        this.reasonPhraseLength =
                ModifiableVariableFactory.safelySetValue(
                        this.reasonPhraseLength, reasonPhraseLength);
    }

    public void setReasonPhraseLength(int reasonPhraseLength) {
        this.setReasonPhraseLength((long) reasonPhraseLength);
    }

    public ModifiableByteArray getReasonPhrase() {
        return reasonPhrase;
    }

    public void setReasonPhrase(byte[] reasonPhrase) {
        this.reasonPhrase =
                ModifiableVariableFactory.safelySetValue(this.reasonPhrase, reasonPhrase);
    }

    public long getErrorCodeConfig() {
        return errorCodeConfig;
    }

    public void setErrorCodeConfig(long errorCodeConfig) {
        this.errorCodeConfig = errorCodeConfig;
    }

    public long getTriggerFrameTypeConfig() {
        return triggerFrameTypeConfig;
    }

    public void setTriggerFrameTypeConfig(long triggerFrameTypeConfig) {
        this.triggerFrameTypeConfig = triggerFrameTypeConfig;
    }

    public long getReasonPhraseLengthConfig() {
        return reasonPhraseLengthConfig;
    }

    public void setReasonPhraseLengthConfig(long reasonPhraseLengthConfig) {
        this.reasonPhraseLengthConfig = reasonPhraseLengthConfig;
    }

    public byte[] getReasonPhraseConfig() {
        return reasonPhraseConfig;
    }

    public void setReasonPhraseConfig(byte[] reasonPhraseConfig) {
        this.reasonPhraseConfig = reasonPhraseConfig;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("ConnectionCloseFrame:");
        sb.append("\n  errorCode: ");
        if (errorCode != null && errorCode.getValue() != null) {
            if (errorCode.getValue() > 0x0100 && errorCode.getValue() < 0x01ff) {
                sb.append("CRYPTO_ERROR (")
                        .append(errorCode.getValue())
                        .append(") -> TLS Alert Description: ")
                        .append(
                                AlertDescription.getAlertDescription(
                                                (byte) (errorCode.getValue() & 0xFF))
                                        .name());

            } else {
                QuicTransportErrorCodes transportErrorCode =
                        QuicTransportErrorCodes.getErrorCode(errorCode.getValue().byteValue());
                if (transportErrorCode != null) {
                    sb.append(transportErrorCode.getName());
                } else {
                    sb.append(errorCode.getValue());
                }
            }

        } else {
            sb.append("null");
        }
        sb.append("\n  triggerFrameType: ");
        if (triggerFrameType != null && triggerFrameType.getValue() != null) {
            if (triggerFrameType.getValue() == 0) {
                sb.append("unknown");
            } else {
                sb.append(QuicFrameType.getFrameType(triggerFrameType.getValue().byteValue()));
            }
        } else {
            sb.append("null");
        }
        sb.append("\n  reasonPhrase: ");
        if (reasonPhrase != null && reasonPhrase.getValue() != null) {
            sb.append(new String(reasonPhrase.getValue(), StandardCharsets.UTF_8));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }
}
