/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
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
import de.rub.nds.tlsattacker.core.https.HttpsRequestMessage;
import de.rub.nds.tlsattacker.core.https.HttpsResponseMessage;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.state.TlsContext;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlTransient;
import java.lang.reflect.Field;
import java.util.List;
import java.util.Random;
import javax.xml.bind.annotation.XmlSeeAlso;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlSeeAlso({ TlsMessage.class, CertificateMessage.class, CertificateVerifyMessage.class,
    CertificateRequestMessage.class, ClientHelloMessage.class, HelloVerifyRequestMessage.class,
    DHClientKeyExchangeMessage.class, DHEServerKeyExchangeMessage.class, ECDHClientKeyExchangeMessage.class,
    ECDHEServerKeyExchangeMessage.class, PskClientKeyExchangeMessage.class, FinishedMessage.class,
    RSAClientKeyExchangeMessage.class, GOSTClientKeyExchangeMessage.class, ServerHelloDoneMessage.class,
    ServerHelloMessage.class, AlertMessage.class, NewSessionTicketMessage.class, KeyUpdateMessage.class,
    ApplicationMessage.class, ChangeCipherSpecMessage.class, SSL2ClientHelloMessage.class,
    SSL2ClientMasterKeyMessage.class, SSL2HandshakeMessage.class, SSL2ServerHelloMessage.class,
    SSL2ServerVerifyMessage.class, UnknownMessage.class, UnknownHandshakeMessage.class, HelloRequestMessage.class,
    HeartbeatMessage.class, SupplementalDataMessage.class, EncryptedExtensionsMessage.class, HttpsRequestMessage.class,
    HttpsResponseMessage.class, PskClientKeyExchangeMessage.class, PskDhClientKeyExchangeMessage.class,
    PskDheServerKeyExchangeMessage.class, PskEcDhClientKeyExchangeMessage.class, PskEcDheServerKeyExchangeMessage.class,
    PskRsaClientKeyExchangeMessage.class, SrpClientKeyExchangeMessage.class, SrpServerKeyExchangeMessage.class,
    EndOfEarlyDataMessage.class, DtlsHandshakeMessageFragment.class, PWDServerKeyExchangeMessage.class,
    RSAServerKeyExchangeMessage.class, PWDClientKeyExchangeMessage.class, PskServerKeyExchangeMessage.class,
    CertificateStatusMessage.class, EmptyClientKeyExchangeMessage.class })
public abstract class ProtocolMessage extends ModifiableVariableHolder {

    @XmlTransient
    protected boolean goingToBeSentDefault = true;
    @XmlTransient
    protected boolean requiredDefault = true;
    @XmlTransient
    protected boolean adjustContextDefault = true;
    /**
     * resulting message
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PLAIN_PROTOCOL_MESSAGE)
    protected ModifiableByteArray completeResultingMessage;
    /**
     * Defines whether this message is necessarily required in the workflow.
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.BEHAVIOR_SWITCH)
    private ModifiableBoolean required;
    /**
     * Defines if the message should be sent during the workflow. Using this flag it is possible to omit a message is
     * sent during the handshake while it is executed to initialize specific variables.
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.BEHAVIOR_SWITCH)
    private ModifiableBoolean goingToBeSent;
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.BEHAVIOR_SWITCH)
    private ModifiableBoolean adjustContext;

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
        this.goingToBeSent = ModifiableVariableFactory.safelySetValue(this.goingToBeSent, goingToBeSent);
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
            ModifiableVariableFactory.safelySetValue(this.completeResultingMessage, completeResultingMessage);
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
        this.adjustContext = ModifiableVariableFactory.safelySetValue(this.adjustContext, adjustContext);
    }

    /**
     * Returns a compact version of the protocol message still containing some additional information.
     */
    public abstract String toCompactString();

    /**
     * Returns the shortest possible string for the protocol message, mostly abbreviations.
     */
    public abstract String toShortString();

    public abstract <S extends ProtocolMessage, T extends ProtocolMessageHandler<S>> T getHandler(TlsContext context);

    public boolean addToTypes(List<ProtocolMessageType> protocolMessageTypes) {
        return false;
    }
}
