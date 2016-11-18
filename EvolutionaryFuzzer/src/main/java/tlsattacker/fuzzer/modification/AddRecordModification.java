/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.modification;

import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import java.util.logging.Logger;

/**
 * A modification which indicates that a new record was added to the
 * WorkflowTrace
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class AddRecordModification extends Modification {

    /**
     * The ProtocolMessage to which the Record was added
     */
    private final ProtocolMessage message;

    public AddRecordModification(ProtocolMessage message) {
        super(ModificationType.ADD_RECORD);
        this.message = message;
    }

    public ProtocolMessage getMessage() {
        return message;
    }

    private static final Logger LOG = Logger.getLogger(AddRecordModification.class.getName());
}
