/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bool.ModifiableBoolean;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.layer.Message;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlSeeAlso;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.List;
import java.util.Random;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlSeeAlso({
    ProtocolMessage.class,
    CertificateMessage.class,
    CertificateVerifyMessage.class,
    CertificateRequestMessage.class,
    ClientHelloMessage.class,
    HelloVerifyRequestMessage.class,
    DHClientKeyExchangeMessage.class,
    DHEServerKeyExchangeMessage.class,
    ECDHClientKeyExchangeMessage.class,
    ECDHEServerKeyExchangeMessage.class,
    PskClientKeyExchangeMessage.class,
    FinishedMessage.class,
    RSAClientKeyExchangeMessage.class,
    GOSTClientKeyExchangeMessage.class,
    ServerHelloDoneMessage.class,
    ServerHelloMessage.class,
    AlertMessage.class,
    NewSessionTicketMessage.class,
    KeyUpdateMessage.class,
    ApplicationMessage.class,
    ChangeCipherSpecMessage.class,
    SSL2ClientHelloMessage.class,
    SSL2ClientMasterKeyMessage.class,
    SSL2Message.class,
    SSL2ServerHelloMessage.class,
    SSL2ServerVerifyMessage.class,
    UnknownSSL2Message.class,
    UnknownMessage.class,
    UnknownHandshakeMessage.class,
    HelloRequestMessage.class,
    HeartbeatMessage.class,
    SupplementalDataMessage.class,
    EncryptedExtensionsMessage.class,
    PskClientKeyExchangeMessage.class,
    PskDhClientKeyExchangeMessage.class,
    PskDheServerKeyExchangeMessage.class,
    PskEcDhClientKeyExchangeMessage.class,
    PskEcDheServerKeyExchangeMessage.class,
    PskRsaClientKeyExchangeMessage.class,
    SrpClientKeyExchangeMessage.class,
    SrpServerKeyExchangeMessage.class,
    EndOfEarlyDataMessage.class,
    DtlsHandshakeMessageFragment.class,
    PWDServerKeyExchangeMessage.class,
    RSAServerKeyExchangeMessage.class,
    PWDClientKeyExchangeMessage.class,
    PskServerKeyExchangeMessage.class,
    CertificateStatusMessage.class,
    EmptyClientKeyExchangeMessage.class,
    EncryptedClientHelloMessage.class
})
public abstract class ProtocolMessage<Self extends ProtocolMessage<?>>
        extends Message<Self, TlsContext> {

    @XmlTransient protected boolean goingToBeSentDefault = true;
    @XmlTransient protected boolean requiredDefault = true;
    @XmlTransient protected boolean adjustContextDefault = true;
    /** resulting message */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PLAIN_PROTOCOL_MESSAGE)
    protected ModifiableByteArray completeResultingMessage;
    /** Defines whether this message is necessarily required in the workflow. */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.BEHAVIOR_SWITCH)
    private ModifiableBoolean required;
    /**
     * Defines if the message should be sent during the workflow. Using this flag it is possible to
     * omit a message is sent during the handshake while it is executed to initialize specific
     * variables.
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.BEHAVIOR_SWITCH)
    private ModifiableBoolean goingToBeSent;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.BEHAVIOR_SWITCH)
    private ModifiableBoolean adjustContext;

    /** content type */
    @XmlTransient protected ProtocolMessageType protocolMessageType;

    public boolean addToTypes(List<ProtocolMessageType> protocolMessageTypes) {
        return protocolMessageTypes.add(getProtocolMessageType());
    }

    @Override
    public boolean isRequired() {
        if (required == null || required.getValue() == null) {
            return requiredDefault;
        }
        return required.getValue();
    }

    public void setRequired(boolean required) {
        this.required = ModifiableVariableFactory.safelySetValue(this.required, required);
    }

    public boolean isGoingToBeSent() {
        if (goingToBeSent == null || goingToBeSent.getValue() == null) {
            return goingToBeSentDefault;
        }
        return goingToBeSent.getValue();
    }

    public void setGoingToBeSent(boolean goingToBeSent) {
        this.goingToBeSent =
                ModifiableVariableFactory.safelySetValue(this.goingToBeSent, goingToBeSent);
    }

    public void setGoingToBeSent(ModifiableBoolean goingToBeSent) {
        this.goingToBeSent = goingToBeSent;
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        return holders;
    }

    @Override
    public Field getRandomModifiableVariableField(Random random) {
        List<Field> fields = getAllModifiableVariableFields();
        int randomField = random.nextInt(fields.size());
        return fields.get(randomField);
    }

    public ModifiableByteArray getCompleteResultingMessage() {
        return completeResultingMessage;
    }

    public void setCompleteResultingMessage(ModifiableByteArray completeResultingMessage) {
        this.completeResultingMessage = completeResultingMessage;
    }

    public void setCompleteResultingMessage(byte[] completeResultingMessage) {
        this.completeResultingMessage =
                ModifiableVariableFactory.safelySetValue(
                        this.completeResultingMessage, completeResultingMessage);
    }

    public boolean getAdjustContext() {
        if (adjustContext == null || adjustContext.getValue() == null) {
            return adjustContextDefault;
        }
        return adjustContext.getValue();
    }

    public void setAdjustContext(ModifiableBoolean adjustContext) {
        this.adjustContext = adjustContext;
    }

    public void setAdjustContext(Boolean adjustContext) {
        this.adjustContext =
                ModifiableVariableFactory.safelySetValue(this.adjustContext, adjustContext);
    }

    @Override
    public abstract ProtocolMessageHandler<Self> getHandler(TlsContext tlsContext);

    @Override
    public abstract ProtocolMessageSerializer<Self> getSerializer(TlsContext tlsContext);

    @Override
    public abstract ProtocolMessagePreparator<Self> getPreparator(TlsContext tlsContext);

    @Override
    public abstract ProtocolMessageParser<Self> getParser(
            TlsContext tlsContext, InputStream stream);

    public boolean isHandshakeMessage() {
        return this instanceof HandshakeMessage;
    }

    public boolean isDtlsHandshakeMessageFragment() {
        return this instanceof DtlsHandshakeMessageFragment;
    }

    public ProtocolMessageType getProtocolMessageType() {
        return protocolMessageType;
    }
}
