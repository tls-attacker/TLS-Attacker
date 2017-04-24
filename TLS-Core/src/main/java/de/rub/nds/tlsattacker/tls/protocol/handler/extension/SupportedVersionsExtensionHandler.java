/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler.extension;

import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.extension.ExtensionParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.extension.SupportedVersionsExtensionParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.extension.ExtensionPreparator;
import de.rub.nds.tlsattacker.tls.protocol.preparator.extension.SupportedVersionsExtensionPreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.SupportedVersionsExtensionSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Nurullah Erinola
 */
public class SupportedVersionsExtensionHandler extends ExtensionHandler<SupportedVersionsExtensionMessage> {

    public SupportedVersionsExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public ExtensionParser getParser(byte[] message, int pointer) {
        return new SupportedVersionsExtensionParser(pointer, message);
    }

    @Override
    public ExtensionPreparator getPreparator(SupportedVersionsExtensionMessage message) {
        return new SupportedVersionsExtensionPreparator(context, message);
    }

    @Override
    public ExtensionSerializer getSerializer(SupportedVersionsExtensionMessage message) {
        return new SupportedVersionsExtensionSerializer(message);
    }

    @Override
    public void adjustTLSContext(SupportedVersionsExtensionMessage message) {
        byte[] versionBytes = message.getSupportedVersions().getValue();
        if (versionBytes.length % HandshakeByteLength.VERSION != 0) {
            throw new AdjustmentException("Could not create resonable ProtocolVersions from VersionBytes");
        }
        List<ProtocolVersion> versionList = new LinkedList<>();
        for (int i = 0; i < versionBytes.length; i = i + HandshakeByteLength.VERSION) {
            byte[] version = Arrays.copyOfRange(versionBytes, i, i + HandshakeByteLength.VERSION);
            ProtocolVersion protocolVersion = ProtocolVersion.getProtocolVersion(version);
            if (protocolVersion == null) {
                LOGGER.warn("Unknown ProtocolVersion:" + ArrayConverter.bytesToHexString(version));
            } else {
                versionList.add(protocolVersion);
            }
        }
        context.setClientSupportedProtocolVersions(versionList);
    }
    
}
