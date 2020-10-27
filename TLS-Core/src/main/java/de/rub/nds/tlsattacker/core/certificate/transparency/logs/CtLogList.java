/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.certificate.transparency.logs;

import java.nio.ByteBuffer;
import java.util.HashMap;

public class CtLogList {

    private HashMap<ByteBuffer, CtLog> ctLogHashMap = new HashMap<>();

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
