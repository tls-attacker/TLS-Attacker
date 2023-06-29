/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestV2ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.RequestItemV2;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.ResponderId;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.CertificateStatusRequestV2ExtensionParserTest;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.RequestItemV2Preparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ResponderIdPreparator;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class CertificateStatusRequestV2ExtensionSerializerTest
        extends AbstractExtensionMessageSerializerTest<
                CertificateStatusRequestV2ExtensionMessage,
                CertificateStatusRequestV2ExtensionSerializer> {

    private final TlsContext context;

    public CertificateStatusRequestV2ExtensionSerializerTest() {
        // noinspection unchecked
        super(
                CertificateStatusRequestV2ExtensionMessage::new,
                CertificateStatusRequestV2ExtensionSerializer::new,
                List.of(
                        (msg, obj) -> msg.setStatusRequestListLength((Integer) obj),
                        (msg, obj) -> {},
                        (msg, obj) -> msg.setStatusRequestList((List<RequestItemV2>) obj)));
        context = new TlsContext();
    }

    public static Stream<Arguments> provideTestVectors() {
        return CertificateStatusRequestV2ExtensionParserTest.provideTestVectors();
    }

    @Override
    protected void setExtensionMessageSpecific(
            List<Object> providedAdditionalValues, List<Object> providedMessageSpecificValues) {
        @SuppressWarnings("unchecked")
        List<RequestItemV2> requestItems =
                (List<RequestItemV2>) providedMessageSpecificValues.get(2);
        for (RequestItemV2 requestItem : requestItems) {
            new RequestItemV2Preparator(context.getChooser(), requestItem).prepare();
            for (ResponderId id : requestItem.getResponderIdList()) {
                new ResponderIdPreparator(context.getChooser(), id).prepare();
            }
        }
        super.setExtensionMessageSpecific(providedAdditionalValues, providedMessageSpecificValues);
    }
}
