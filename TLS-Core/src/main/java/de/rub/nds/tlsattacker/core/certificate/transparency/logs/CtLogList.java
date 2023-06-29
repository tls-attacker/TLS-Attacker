/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate.transparency.logs;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

public class CtLogList {

    private Map<ByteBuffer, CtLog> ctLogHashMap = new HashMap<>();

    public CtLog getCtLog(byte[] logId) {
        ByteBuffer byteBuffer = ByteBuffer.wrap(logId.clone());
        if (ctLogHashMap.containsKey(byteBuffer)) {
            return ctLogHashMap.get(byteBuffer);
        } else {
            return null;
        }
    }

    public void addCtLog(CtLog log) {
        ByteBuffer byteBuffer = ByteBuffer.wrap(log.getLogId().clone());
        ctLogHashMap.put(byteBuffer, log);
    }
}
