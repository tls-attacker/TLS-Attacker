/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.message;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.tls.protocol.serializer.HelloVerifyRequestSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 * @author Florian Pfützenreuter <Florian.Pfuetzenreuter@rub.de>
 */
public class HelloVerifyRequestMessage extends HandshakeMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByteArray protocolVersion = null;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableByte cookieLength = null;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.COOKIE)
    ModifiableByteArray cookie = null;

    public HelloVerifyRequestMessage() {
        super(HandshakeMessageType.HELLO_VERIFY_REQUEST);
        protocolVersion = ModifiableVariableFactory.safelySetValue(protocolVersion, ProtocolVersion.DTLS12.getValue());
        cookieLength = ModifiableVariableFactory.safelySetValue(cookieLength, (byte) 0);
        cookie = ModifiableVariableFactory.safelySetValue(cookie, new byte[0]);
        this.setIncludeInDigest(false);
    }

    public HelloVerifyRequestMessage(TlsConfig tlsConfig) {
        super(tlsConfig, HandshakeMessageType.HELLO_VERIFY_REQUEST);
        protocolVersion = ModifiableVariableFactory.safelySetValue(protocolVersion, ProtocolVersion.DTLS12.getValue());
        cookieLength = ModifiableVariableFactory.safelySetValue(cookieLength, (byte) 0);
        cookie = ModifiableVariableFactory.safelySetValue(cookie, new byte[0]);
        this.setIncludeInDigest(false);
    }

    public ModifiableByteArray getProtocolVersion() {
        return protocolVersion;
    }

    public ModifiableByteArray getCookie() {
        return cookie;
    }

    public ModifiableByte getCookieLength() {
        return cookieLength;
    }

    public void setProtocolVersion(byte[] protocolVersion) {
        this.protocolVersion = ModifiableVariableFactory.safelySetValue(this.protocolVersion, protocolVersion);
    }

    public void setProtocolVersion(ModifiableByteArray protocolVersion) {
        this.protocolVersion = protocolVersion;
    }

    public void setCookie(byte[] cookie) {
        this.cookie = ModifiableVariableFactory.safelySetValue(this.cookie, cookie);
    }

    public void setCookie(ModifiableByteArray cookie) {
        this.cookie = cookie;
    }

    public void setCookieLength(byte cookieLength) {
        this.cookieLength = ModifiableVariableFactory.safelySetValue(this.cookieLength, cookieLength);
    }

    public void setCookieLength(ModifiableByte cookieLength) {
        this.cookieLength = cookieLength;
    }

    @Override
    public Serializer getSerializer() {
        return new HelloVerifyRequestSerializer(this);
    }
}
