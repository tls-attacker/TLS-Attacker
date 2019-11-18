/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PrintSecretsAction extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public PrintSecretsAction() {
    }

    public PrintSecretsAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        TlsContext ctx = state.getTlsContext(connectionAlias);
        StringBuilder sb = new StringBuilder("\n\nContext: " + ctx);
        sb.append("\n  (Record Layer) ");
        if (ctx.getSelectedCipherSuite() == null) {
            sb.append("\n  CipherSuite: null");
        } else {
            sb.append("\n  CipherSuite: ").append(ctx.getSelectedCipherSuite().name());
        }

        sb.append("\n  (RSA Key Exchange) ");
        if (ctx.getChooser().getServerRSAPublicKey() == null) {
            sb.append("\n  ServerRsaPublicKey (chooser): null");
        } else {
            sb.append("\n  ServerRsaPublicKey (chooser): ");
            sb.append(ctx.getChooser().getServerRSAPublicKey());
        }
        if (ctx.getChooser().getServerRsaModulus() == null) {
            sb.append("\n  ServerRsaModulus(chooser): null");
        } else {
            sb.append("\n  ServerRsaModulus (chooser): ");
            sb.append(toIndentedString(ArrayConverter.bigIntegerToByteArray(ctx.getChooser().getServerRsaModulus())));
        }

        sb.append("\n\n  (Handshake) ");
        sb.append("\n  Client Random: ").append(toIndentedString(ctx.getClientRandom()));
        sb.append("\n  Server Random: ").append(toIndentedString(ctx.getServerRandom()));
        sb.append("\n  PreMasterSecret: ").append(toIndentedString(ctx.getPreMasterSecret()));
        sb.append("\n  MasterSecret: ").append(toIndentedString(ctx.getMasterSecret()));

        if (ctx.getLastClientVerifyData() == null) {
            sb.append("\n  LastClientVerifyData: null");
        } else {
            sb.append("\n  LastClientVerifyData: ").append(toIndentedString(ctx.getLastClientVerifyData()));
        }
        if (ctx.getLastServerVerifyData() == null) {
            sb.append("\n  LastServerVerifyData: null");
        } else {
            sb.append("\n  LastServerVerifyData: ").append(toIndentedString(ctx.getLastServerVerifyData()));
        }

        CONSOLE.info(sb.append("\n").toString());

    }

    private String toIndentedString(byte[] bytes) {
        return ArrayConverter.bytesToHexString(bytes).replace("\n", "\n  ");
    }

    @Override
    public boolean executedAsPlanned() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void reset() {
    }

}
