/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
/**
 /**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * <p>Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsattacker.core.record;

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
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

public class RecordTest {

    Record record;
    Chooser chooser;
    Encryptor encryptor;
    RecordCompressor compressor;
    Context context;

    @Before
    public void setUp() {
        record = new Record();
        Config config = Config.createConfig();
        context = new Context(new Config());
        chooser = ChooserFactory.getChooser(ChooserType.DEFAULT, context, config);
    }

    /**
     * Test of getRecordPreparator method, of class Record.
     */
    @Test
    public void testGetRecordPreparator() {
        assertEquals(record
            .getRecordPreparator(context.getTlsContext(), encryptor, compressor, ProtocolMessageType.ALERT).getClass(),
            RecordPreparator.class);
    }

    /**
     * Test of getRecordParser method, of class Record.
     */
    @Test
    public void testGetRecordParser() {
        assertEquals(record.getRecordParser(new ByteArrayInputStream(new byte[0]), ProtocolVersion.TLS10).getClass(),
            RecordParser.class);
        assertEquals(record.getRecordParser(new ByteArrayInputStream(new byte[0]), ProtocolVersion.TLS11).getClass(),
            RecordParser.class);
        assertEquals(record.getRecordParser(new ByteArrayInputStream(new byte[0]), ProtocolVersion.TLS12).getClass(),
            RecordParser.class);
        assertEquals(record.getRecordParser(new ByteArrayInputStream(new byte[0]), ProtocolVersion.TLS13).getClass(),
            RecordParser.class);
    }

    /**
     * Test of getRecordSerializer method, of class Record.
     */
    @Test
    public void testGetRecordSerializer() {
        assertEquals(record.getRecordSerializer().getClass(), RecordSerializer.class);
    }

}
