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
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
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

    private ConnectionCloseFrame() {}

    public ConnectionCloseFrame(boolean isQuicLayer) {
        if (isQuicLayer) {
            setFrameType(QuicFrameType.CONNECTION_CLOSE_QUIC_FRAME);
        } else {
            setFrameType(QuicFrameType.CONNECTION_CLOSE_APPLICATION_FRAME);
        }
        ackEliciting = false;
        this.setReasonPhraseLength(0);
        this.setTriggerFrameType(0);
    }

    public ConnectionCloseFrame(long errorCode) {
        this(true);
        this.errorCode = ModifiableVariableFactory.safelySetValue(this.errorCode, errorCode);
    }

    public ConnectionCloseFrame(long errorCode, String reasonPhrase) {
        this(errorCode);
        this.setReasonPhrase(reasonPhrase.getBytes(StandardCharsets.UTF_8));
        this.setReasonPhraseLength(this.reasonPhrase.getValue().length);
    }

    public ConnectionCloseFrame(int errorCode, String reasonPhrase, long triggerFrameType) {
        this(errorCode, reasonPhrase);
        this.setTriggerFrameType(triggerFrameType);
    }

    @Override
    public ConnectionCloseFrameHandler getHandler(QuicContext context) {
        return new ConnectionCloseFrameHandler(context);
    }

    @Override
    public ConnectionCloseFrameSerializer getSerializer(QuicContext context) {
        return new ConnectionCloseFrameSerializer(this);
    }

    @Override
    public ConnectionCloseFramePreparator getPreparator(QuicContext context) {
        return new ConnectionCloseFramePreparator(context.getChooser(), this);
    }

    @Override
    public ConnectionCloseFrameParser getParser(QuicContext context, InputStream stream) {
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
                sb.append(
                        QuicTransportErrorCodes.getErrorCode(errorCode.getValue().byteValue())
                                .getName());
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
