/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @param <T> The ExtensionMessage that should be prepared
 */
public abstract class ExtensionPreparator<T extends ExtensionMessage> extends Preparator<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ExtensionMessage msg;
    private byte[] content;
    private final ExtensionSerializer<T> serializer;

    public ExtensionPreparator(Chooser chooser, T message, ExtensionSerializer<T> serializer) {
        super(chooser, message);
        this.msg = message;
        this.serializer = serializer;
    }

    public ExtensionPreparator(Chooser chooser, T message) {
        super(chooser, message);
        this.msg = message;
        this.serializer = message.getSerializer(chooser.getContext().getTlsContext());
    }

    @Override
    public final void prepare() {
        prepareExtensionType(msg);
        prepareExtensionContent();
        content = serializer.serializeExtensionContent();
        prepareExtensionContentBytes(msg);
        prepareExtensionLength(msg);
        prepareExtensionBytes(msg);
    }

    @Override
    public final void afterPrepare() {
        prepareExtensionType(msg);
        afterPrepareExtensionContent();
        content = serializer.serializeExtensionContent();
        prepareExtensionContentBytes(msg);
        prepareExtensionLength(msg);
        prepareExtensionBytes(msg);
    }

    public abstract void prepareExtensionContent();

    public void afterPrepareExtensionContent() {}

    private void prepareExtensionType(ExtensionMessage msg) {
        msg.setExtensionType(msg.getExtensionTypeConstant().getValue());
        LOGGER.debug("ExtensionType: {}", msg.getExtensionType().getValue());
    }

    private void prepareExtensionLength(ExtensionMessage msg) {
        msg.setExtensionLength(content.length);
        LOGGER.debug("ExtensionLength: " + msg.getExtensionLength().getValue());
    }

    private void prepareExtensionBytes(ExtensionMessage msg) {
        msg.setExtensionBytes(serializer.serialize());
        LOGGER.debug("ExtensionBytes: {}", msg.getExtensionBytes().getValue());
    }

    private void prepareExtensionContentBytes(ExtensionMessage msg) {
        msg.setExtensionContent(content);
        LOGGER.debug("ExtensionContent: {}", msg.getExtensionContent().getValue());
    }
}
