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
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.DebugExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.DebugExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.DebugExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.DebugExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** Class representing a Debug Extension Message. */
@XmlRootElement(name = "DebugExtension")
public class DebugExtensionMessage extends ExtensionMessage {

    public DebugExtensionMessage() {
        super(ExtensionType.GREASE_16);
    }

    private ModifiableString debugContent;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger debugContentLength;

    public ModifiableString getDebugContent() {
        return debugContent;
    }

    public void setDebugContent(ModifiableString debugContent) {
        this.debugContent = debugContent;
    }

    public void setDebugContent(String content) {
        this.debugContent = ModifiableVariableFactory.safelySetValue(debugContent, content);
    }

    @Override
    public ExtensionHandler<DebugExtensionMessage> getHandler(Context context) {
        return new DebugExtensionHandler(context.getTlsContext());
    }

    @Override
    public ExtensionSerializer<DebugExtensionMessage> getSerializer(Context context) {
        return new DebugExtensionSerializer(this);
    }

    @Override
    public ExtensionPreparator<DebugExtensionMessage> getPreparator(Context context) {
        return new DebugExtensionPreparator(context.getChooser(), this);
    }

    @Override
    public ExtensionParser<DebugExtensionMessage> getParser(Context context, InputStream stream) {
        return new DebugExtensionParser(stream, context.getTlsContext());
    }
}
