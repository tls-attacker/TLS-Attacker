/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.dtls;

import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author Nurullah Erinola - nurullah.erinola@rub.de
 */
public class CssCollector {

    private List<AbstractRecord> records;

    private boolean interpreted = false;

    public CssCollector() {
        records = new ArrayList<AbstractRecord>();
    }

    public void addCssRecord(AbstractRecord record) {
        records.add(record);
    }

    public List<AbstractRecord> getCssRecords() {
        return records;
    }

    public boolean isInterpreted() {
        return interpreted;
    }

    public void setInterpreted(boolean interpreted) {
        this.interpreted = interpreted;
    }
}
