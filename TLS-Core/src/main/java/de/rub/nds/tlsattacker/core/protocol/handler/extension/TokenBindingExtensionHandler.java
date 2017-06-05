/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TokenBindingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.TokenBindingExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.TokenBindingExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.TokenBindingExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.util.ArrayList;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class TokenBindingExtensionHandler extends ExtensionHandler<TokenBindingExtensionMessage> {

    public TokenBindingExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public ExtensionParser getParser(byte[] message, int pointer) {
        LOGGER.debug("The token binding extension handler returned the parser.");
        return new TokenBindingExtensionParser(pointer, message);
    }

    @Override
    public ExtensionPreparator getPreparator(TokenBindingExtensionMessage message) {
        LOGGER.debug("The token binding extension handler returned the preparator.");
        return new TokenBindingExtensionPreparator(context, message);
    }

    @Override
    public ExtensionSerializer getSerializer(TokenBindingExtensionMessage message) {
        LOGGER.debug("The token binding extension handler returned the serializer.");
        return new TokenBindingExtensionSerializer(message);
    }

    @Override
    public void adjustTLSContext(TokenBindingExtensionMessage message) {
        context.setTokenBindingMajorVersion(TokenBindingVersion.getExtensionType(message.getMajorTokenbindingVersion().getValue()));
        context.setTokenBindingMinorVersion(TokenBindingVersion.getExtensionType(message.getMinorTokenbindingVersion().getValue()));
        ArrayList<TokenBindingKeyParameters> tokenbindingKeyParameters = new ArrayList<>();
        for (byte kp : message.getTokenbindingKeyParameters().getValue()) {
            tokenbindingKeyParameters.add(TokenBindingKeyParameters.getExtensionType(kp));
        }
        context.setTokenBindingKeyParameters(tokenbindingKeyParameters
                .toArray(new TokenBindingKeyParameters[tokenbindingKeyParameters.size()]));
        LOGGER.debug("The token binding extension handler adjusted the TLS context.");
    }

}
