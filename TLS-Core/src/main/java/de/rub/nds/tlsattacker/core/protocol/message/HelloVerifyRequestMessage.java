/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.HelloVerifyRequestHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.HelloVerifyRequestParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.HelloVerifyRequestPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.HelloVerifyRequestSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.Objects;

@XmlRootElement(name = "HelloVerifyRequest")
public class HelloVerifyRequestMessage extends HandshakeMessage {

    @ModifiableVariableProperty private ModifiableByteArray protocolVersion = null;

    @ModifiableVariableProperty(purpose = ModifiableVariableProperty.Purpose.LENGTH)
    private ModifiableByte cookieLength = null;

    @ModifiableVariableProperty private ModifiableByteArray cookie = null;

    public HelloVerifyRequestMessage() {
        super(HandshakeMessageType.HELLO_VERIFY_REQUEST);
        isIncludeInDigestDefault = false;
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
        this.protocolVersion =
                ModifiableVariableFactory.safelySetValue(this.protocolVersion, protocolVersion);
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
        this.cookieLength =
                ModifiableVariableFactory.safelySetValue(this.cookieLength, cookieLength);
    }

    public void setCookieLength(ModifiableByte cookieLength) {
        this.cookieLength = cookieLength;
    }

    @Override
    public HelloVerifyRequestHandler getHandler(Context context) {
        return new HelloVerifyRequestHandler(context.getTlsContext());
    }

    @Override
    public HelloVerifyRequestParser getParser(Context context, InputStream stream) {
        return new HelloVerifyRequestParser(stream, context.getTlsContext());
    }

    @Override
    public HelloVerifyRequestPreparator getPreparator(Context context) {
        return new HelloVerifyRequestPreparator(context.getChooser(), this);
    }

    @Override
    public HelloVerifyRequestSerializer getSerializer(Context context) {
        return new HelloVerifyRequestSerializer(this);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("HelloVerifyRequestMessage:");
        sb.append("\n  ProtocolVersion: ");
        if (protocolVersion != null && protocolVersion.getValue() != null) {
            sb.append(DataConverter.bytesToHexString(protocolVersion.getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Cookie Length: ");
        if (cookieLength != null && cookieLength.getValue() != null) {
            sb.append(cookieLength.getValue());
        } else {
            sb.append("null");
        }
        sb.append("\n  Cookie: ");
        if (cookie != null && cookie.getValue() != null) {
            sb.append(DataConverter.bytesToHexString(cookie.getValue()));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    @Override
    public String toShortString() {
        return "HVR";
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 31 * hash + Objects.hashCode(this.protocolVersion);
        hash = 31 * hash + Objects.hashCode(this.cookieLength);
        hash = 31 * hash + Objects.hashCode(this.cookie);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final HelloVerifyRequestMessage other = (HelloVerifyRequestMessage) obj;
        if (!Objects.equals(this.protocolVersion, other.protocolVersion)) {
            return false;
        }
        if (!Objects.equals(this.cookieLength, other.cookieLength)) {
            return false;
        }
        return Objects.equals(this.cookie, other.cookie);
    }
}
