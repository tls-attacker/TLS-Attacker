/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.stun.model;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bool.ModifiableBoolean;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.stun.StunMessageClass;
import de.rub.nds.tlsattacker.core.constants.stun.StunMethodType;
import de.rub.nds.tlsattacker.core.layer.Message;
import de.rub.nds.tlsattacker.core.layer.context.IceContext;
import de.rub.nds.tlsattacker.core.stun.handler.StunMessageHandler;
import de.rub.nds.tlsattacker.core.stun.parser.StunMessageParser;
import de.rub.nds.tlsattacker.core.stun.preparator.StunMessagePreparator;
import de.rub.nds.tlsattacker.core.stun.serializer.StunMessageSerializer;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;

public class StunMessage extends Message<IceContext> {

    private final StunMessageClass classType;

    private final StunMethodType methodType;

    /** 10 bit */
    private ModifiableByteArray stunMethodType;

    /** 2 bit */
    private ModifiableByteArray stunMessageClass;

    /** 2 bytes */
    private ModifiableByteArray stunMessageTypeBytes;

    /** 2 bytes */
    private ModifiableInteger messageLength;

    /** 4 bytes */
    private ModifiableBoolean magicCookiePresent;

    /** 12 bytes */
    private ModifiableByteArray transactionId;

    private List<StunAttribute> attributeList;

    private ModifiableByteArray completeMessageBytes;

    public StunMessage(StunMessageClass classType, StunMethodType methodType) {
        attributeList = new LinkedList<>();
        this.classType = classType;
        this.methodType = methodType;
    }
    
    public ModifiableByteArray getCompleteMessageBytes() {
        return completeMessageBytes;
    }

    public void setCompleteMessageBytes(ModifiableByteArray completeMessageBytes) {
        this.completeMessageBytes = completeMessageBytes;
    }

    public void setCompleteMessageBytes(byte[] completeMessageBytes) {
        this.completeMessageBytes =
                ModifiableVariableFactory.safelySetValue(this.completeMessageBytes, completeMessageBytes);
    }

    public StunMessageClass getClassType() {
        return classType;
    }

    public StunMethodType getMethodType() {
        return methodType;
    }

    public ModifiableByteArray getStunMethodType() {
        return stunMethodType;
    }

    public void setStunMethodType(ModifiableByteArray stunMethodType) {
        this.stunMethodType = stunMethodType;
    }

    public void setStunMethodType(byte[] stunMethodType) {
        this.stunMethodType =
                ModifiableVariableFactory.safelySetValue(this.stunMethodType, stunMethodType);
    }

    public ModifiableByteArray getStunMessageClass() {
        return stunMessageClass;
    }

    public void setStunMessageClass(ModifiableByteArray stunMessageClass) {
        this.stunMessageClass = stunMessageClass;
    }

    public void setStunMessageClass(byte[] stunMessageClass) {
        this.stunMessageClass =
                ModifiableVariableFactory.safelySetValue(this.stunMessageClass, stunMessageClass);
    }

    public ModifiableByteArray getStunMessageTypeBytes() {
        return stunMessageTypeBytes;
    }

    public void setStunMessageTypeBytes(ModifiableByteArray stunMessageType) {
        this.stunMessageTypeBytes = stunMessageType;
    }

    public void setStunMessageTypeBytes(byte[] stunMessageType) {
        this.stunMessageTypeBytes =
                ModifiableVariableFactory.safelySetValue(
                        this.stunMessageTypeBytes, stunMessageType);
    }

    public ModifiableInteger getMessageLength() {
        return messageLength;
    }

    public void setMessageLength(ModifiableInteger messageLength) {
        this.messageLength = messageLength;
    }

    public void setMessageLength(int messageLength) {
        this.messageLength =
                ModifiableVariableFactory.safelySetValue(this.messageLength, messageLength);
    }

    public ModifiableBoolean getMagicCookiePresent() {
        return magicCookiePresent;
    }

    public void setMagicCookiePresent(ModifiableBoolean magicCookiePresent) {
        this.magicCookiePresent = magicCookiePresent;
    }

    public void setMagicCookiePresent(boolean magicCookiePresent) {
        this.magicCookiePresent =
                ModifiableVariableFactory.safelySetValue(
                        this.magicCookiePresent, magicCookiePresent);
    }

    public ModifiableByteArray getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(ModifiableByteArray transactionId) {
        this.transactionId = transactionId;
    }

    public void setTransactionId(byte[] transactionId) {
        this.transactionId =
                ModifiableVariableFactory.safelySetValue(this.transactionId, transactionId);
    }

    public List<StunAttribute> getAttributeList() {
        return attributeList;
    }

    public void setAttributeList(List<StunAttribute> attributeList) {
        this.attributeList = attributeList;
    }

    @Override
    public StunMessageParser getParser(IceContext context, InputStream stream) {
        return new StunMessageParser(stream);
    }

    @Override
    public StunMessagePreparator getPreparator(IceContext context) {
        return new StunMessagePreparator(context.getChooser(), this);
    }

    @Override
    public StunMessageSerializer getSerializer(IceContext context) {
        return new StunMessageSerializer(context, this);
    }

    @Override
    public StunMessageHandler getHandler(IceContext context) {
        return new StunMessageHandler(context);
    }

    @Override
    public String toShortString() {
        return "STUN:" + classType + ":" + methodType;
    }
}
