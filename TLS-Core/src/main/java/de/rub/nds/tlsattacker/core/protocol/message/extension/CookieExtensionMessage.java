/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.CookieExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.CookieExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.CookieExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.CookieExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** The cookie extension used in TLS 1.3 */
@XmlRootElement(name = "CookieExtension")
public class CookieExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty(purpose = ModifiableVariableProperty.Purpose.LENGTH)
    private ModifiableInteger cookieLength;

    @ModifiableVariableProperty private ModifiableByteArray cookie;

    public CookieExtensionMessage() {
        super(ExtensionType.COOKIE);
    }

    public ModifiableInteger getCookieLength() {
        return cookieLength;
    }

    public void setCookieLength(ModifiableInteger cookieLength) {
        this.cookieLength = cookieLength;
    }

    public void setCookieLength(int length) {
        this.cookieLength = ModifiableVariableFactory.safelySetValue(cookieLength, length);
    }

    public ModifiableByteArray getCookie() {
        return cookie;
    }

    public void setCookie(ModifiableByteArray cookie) {
        this.cookie = cookie;
    }

    public void setCookie(byte[] cookieBytes) {
        this.cookie = ModifiableVariableFactory.safelySetValue(cookie, cookieBytes);
    }

    @Override
    public CookieExtensionParser getParser(Context context, InputStream stream) {
        return new CookieExtensionParser(stream, context.getTlsContext());
    }

    @Override
    public CookieExtensionPreparator getPreparator(Context context) {
        return new CookieExtensionPreparator(context.getChooser(), this);
    }

    @Override
    public CookieExtensionSerializer getSerializer(Context context) {
        return new CookieExtensionSerializer(this);
    }

    @Override
    public CookieExtensionHandler getHandler(Context context) {
        return new CookieExtensionHandler(context.getTlsContext());
    }
}
