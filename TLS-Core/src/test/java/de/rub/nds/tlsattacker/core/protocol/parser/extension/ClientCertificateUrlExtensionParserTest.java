/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientCertificateUrlExtensionMessage;
import org.junit.jupiter.params.provider.Arguments;

import java.util.List;
import java.util.stream.Stream;

public class ClientCertificateUrlExtensionParserTest
    extends AbstractExtensionParserTest<ClientCertificateUrlExtensionMessage, ClientCertificateUrlExtensionParser> {

    public ClientCertificateUrlExtensionParserTest() {
        super(ClientCertificateUrlExtensionParser::new);
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(Arguments.of(new byte[] { 0x00, 0x02, 0x00, 0x00 }, List.of(),
            ExtensionType.CLIENT_CERTIFICATE_URL, 0, List.of()));
    }
}
