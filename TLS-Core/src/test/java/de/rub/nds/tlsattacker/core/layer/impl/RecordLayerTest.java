/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.impl;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTcpTransportHandler;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import java.io.IOException;
import java.util.List;
import org.bouncycastle.util.Arrays;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class RecordLayerTest {

    private Config config;

    private TlsContext tlsContext;

    private State state;

    private FakeTcpTransportHandler transportHandler;

    @BeforeEach
    public void setUp() throws IOException {
        config = new Config();
        config.setDefaultLayerConfiguration(StackConfiguration.TLS);
        config.setHighestProtocolVersion(ProtocolVersion.TLS12);
        state = new State(config);
        tlsContext = state.getTlsContext();
        transportHandler = new FakeTcpTransportHandler(null);
        tlsContext.setTransportHandler(transportHandler);
    }

    @Test
    public void testCompleteRecordModificationApplies() {
        ApplicationMessage dummyMessage = new ApplicationMessage();
        dummyMessage.setDataConfig(new byte[] {1, 1, 1, 1});
        Record modifiedRecord = new Record();
        byte[] specificSerializedBytes = new byte[] {2, 2, 2, 2, 2, 2, 2, 2, 2, 2};
        modifiedRecord.setCompleteRecordBytes(Modifiable.explicit(specificSerializedBytes));
        SendAction sendRecord = new SendAction("client", dummyMessage);
        sendRecord.setConfiguredRecords(List.of(modifiedRecord));
        sendRecord.execute(state);
        Assertions.assertArrayEquals(specificSerializedBytes, transportHandler.getSentBytes());
    }

    @Test
    public void testRecordMessageModificationApplies() {
        ClientHelloMessage dummyMessage = new ClientHelloMessage(config);
        Record modifiedRecord = new Record();
        byte[] specificSerializedBytes = new byte[] {2, 2, 2, 2};
        modifiedRecord.setCleanProtocolMessageBytes(Modifiable.explicit(specificSerializedBytes));
        SendAction sendRecord = new SendAction("client", dummyMessage);
        sendRecord.setConfiguredRecords(List.of(modifiedRecord));
        sendRecord.execute(state);
        byte[] completeSerializedExpected =
                Arrays.concatenate(new byte[] {22, 3, 3, 0, 4}, specificSerializedBytes);
        Assertions.assertArrayEquals(completeSerializedExpected, transportHandler.getSentBytes());
    }
}
