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
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.SRPExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SRPExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.SRPExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SRPExtensionSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** This extension is defined in RFC5054 */
@XmlRootElement(name = "SRPExtension")
public class SRPExtensionMessage extends ExtensionMessage<SRPExtensionMessage> {

    // UTF-8 encoded and according to RFC 4013 with the SASLprep profile
    @ModifiableVariableProperty private ModifiableByteArray srpIdentifier;

    @ModifiableVariableProperty private ModifiableInteger srpIdentifierLength;

    public SRPExtensionMessage() {
        super(ExtensionType.SRP);
    }

    public ModifiableByteArray getSrpIdentifier() {
        return srpIdentifier;
    }

    public void setSrpIdentifier(ModifiableByteArray srpIdentifier) {
        this.srpIdentifier = srpIdentifier;
    }

    public void setSrpIdentifier(byte[] srpIdentifier) {
        this.srpIdentifier =
                ModifiableVariableFactory.safelySetValue(this.srpIdentifier, srpIdentifier);
    }

    public ModifiableInteger getSrpIdentifierLength() {
        return srpIdentifierLength;
    }

    public void setSrpIdentifierLength(ModifiableInteger srpIdentifierLength) {
        this.srpIdentifierLength = srpIdentifierLength;
    }

    public void setSrpIdentifierLength(int srpIdentifierLength) {
        this.srpIdentifierLength =
                ModifiableVariableFactory.safelySetValue(
                        this.srpIdentifierLength, srpIdentifierLength);
    }

    @Override
    public SRPExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new SRPExtensionParser(stream, tlsContext);
    }

    @Override
    public SRPExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new SRPExtensionPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public SRPExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new SRPExtensionSerializer(this);
    }

    @Override
    public SRPExtensionHandler getHandler(TlsContext tlsContext) {
        return new SRPExtensionHandler(tlsContext);
    }
}
