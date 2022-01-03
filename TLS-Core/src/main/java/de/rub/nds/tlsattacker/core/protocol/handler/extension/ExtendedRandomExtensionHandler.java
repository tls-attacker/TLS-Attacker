/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedRandomExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtendedRandomExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtendedRandomExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtendedRandomExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This Class handles the Extended Random Extension as defined as in
 * https://tools.ietf.org/html/draft-rescorla-tls-extended-random-02
 */
public class ExtendedRandomExtensionHandler extends ExtensionHandler<ExtendedRandomExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ExtendedRandomExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public ExtendedRandomExtensionParser getParser(byte[] message, int pointer, Config config) {
        return new ExtendedRandomExtensionParser(pointer, message, config);
    }

    @Override
    public ExtendedRandomExtensionPreparator getPreparator(ExtendedRandomExtensionMessage message) {
        return new ExtendedRandomExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public ExtendedRandomExtensionSerializer getSerializer(ExtendedRandomExtensionMessage message) {
        return new ExtendedRandomExtensionSerializer(message);
    }

    @Override
    public void adjustTLSExtensionContext(ExtendedRandomExtensionMessage message) {
        if (context.getTalkingConnectionEndType().equals(ConnectionEndType.SERVER)) {
            context.setServerExtendedRandom(message.getExtendedRandom().getValue());
            LOGGER.debug("The context server extended Random was set to "
                + ArrayConverter.bytesToHexString(message.getExtendedRandom()));

        }
        if (context.getTalkingConnectionEndType().equals(ConnectionEndType.CLIENT)) {
            context.setClientExtendedRandom(message.getExtendedRandom().getValue());
            LOGGER.debug("The context client extended Random was set to "
                + ArrayConverter.bytesToHexString(message.getExtendedRandom()));

        }

        // If both extended Randoms are received (i.e. client and server agreed
        // on using extended Random)
        // then extend the client and server random for premaster computations.
        if (!(context.getClientExtendedRandom() == null) && !(context.getServerExtendedRandom() == null)) {
            LOGGER.debug("Extended Random was agreed on. Concatenating extended Randoms to normal Randoms.");
            byte[] clientConcatRandom =
                ArrayConverter.concatenate(context.getClientRandom(), context.getClientExtendedRandom());
            byte[] serverConcatRandom =
                ArrayConverter.concatenate(context.getServerRandom(), context.getServerExtendedRandom());
            context.setClientRandom(clientConcatRandom);
            LOGGER.debug("ClientRandom: " + ArrayConverter.bytesToHexString(context.getClientRandom()));
            context.setServerRandom(serverConcatRandom);
            LOGGER.debug("ServerRandom: " + ArrayConverter.bytesToHexString(context.getServerRandom()));
        }

    }
}
