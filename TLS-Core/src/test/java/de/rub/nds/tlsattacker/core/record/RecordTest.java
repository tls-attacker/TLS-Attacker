/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.record;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ChooserType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.compressor.RecordCompressor;
import de.rub.nds.tlsattacker.core.record.crypto.Encryptor;
import de.rub.nds.tlsattacker.core.record.parser.RecordParser;
import de.rub.nds.tlsattacker.core.record.preparator.RecordPreparator;
import de.rub.nds.tlsattacker.core.record.serializer.RecordSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.core.workflow.chooser.ChooserFactory;
import java.io.ByteArrayInputStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class RecordTest {

    private Record record;
    private Chooser chooser;
    private Encryptor encryptor;
    private RecordCompressor compressor;
    private Context context;

    @BeforeEach
    public void setUp() {
        record = new Record();
        Config config = Config.createConfig();
        context = new Context(new Config());
        chooser = ChooserFactory.getChooser(ChooserType.DEFAULT, context, config);
    }

    /** Test of getRecordPreparator method, of class Record. */
    @Test
    public void testGetRecordPreparator() {
        assertEquals(
                record.getRecordPreparator(
                                context.getTlsContext(),
                                encryptor,
                                compressor,
                                ProtocolMessageType.ALERT)
                        .getClass(),
                RecordPreparator.class);
    }

    /** Test of getRecordParser method, of class Record. */
    @Test
    public void testGetRecordParser() {
        assertEquals(
                record.getRecordParser(
                                new ByteArrayInputStream(new byte[0]),
                                ProtocolVersion.TLS10,
                                context.getTlsContext())
                        .getClass(),
                RecordParser.class);
        assertEquals(
                record.getRecordParser(
                                new ByteArrayInputStream(new byte[0]),
                                ProtocolVersion.TLS11,
                                context.getTlsContext())
                        .getClass(),
                RecordParser.class);
        assertEquals(
                record.getRecordParser(
                                new ByteArrayInputStream(new byte[0]),
                                ProtocolVersion.TLS12,
                                context.getTlsContext())
                        .getClass(),
                RecordParser.class);
        assertEquals(
                record.getRecordParser(
                                new ByteArrayInputStream(new byte[0]),
                                ProtocolVersion.TLS13,
                                context.getTlsContext())
                        .getClass(),
                RecordParser.class);
    }

    /** Test of getRecordSerializer method, of class Record. */
    @Test
    public void testGetRecordSerializer() {
        assertEquals(record.getRecordSerializer().getClass(), RecordSerializer.class);
    }
}
