/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.dtls;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CcsManager {

    private static final Logger LOGGER = LogManager.getLogger(CcsManager.class);

    private Config config;

    private Map<CcsKey, CcsCollector> cssMessages;

    public CcsManager(Config config) {
        cssMessages = new HashMap<>();
        this.config = config;
    }

    public void addCssMessage(AbstractRecord record, Integer epoch) {
        CcsKey key = new CcsKey(epoch);
        CcsCollector collector = cssMessages.get(key);
        if (collector == null) {
            collector = new CcsCollector();
            cssMessages.put(key, collector);
        }
        collector.addCssRecord(record);
    }

    public byte[] getUninterpretedCssMessages(Integer epoch) {
        CcsKey key = new CcsKey(epoch);
        CcsCollector collector = cssMessages.get(key);
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        if (!collector.isInterpreted()) {
            collector.setInterpreted(true);
            try {
                stream.write(cssMessages.get(key).getCssRecords().get(0).getCleanProtocolMessageBytes().getValue());
            } catch (IOException ex) {
                LOGGER.warn("Could not write CleanProtocolMessage bytes to Array");
                LOGGER.debug(ex);
            }
        }
        return stream.toByteArray();
    }
}
