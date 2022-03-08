package de.rub.nds.tlsattacker.core.https;

import de.rub.nds.tlsattacker.core.protocol.Preparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public abstract class HttpsMessagePreparator<T extends HttpsMessage> extends Preparator<T> {

    protected final T message;

    public HttpsMessagePreparator(Chooser chooser, T message) {
        super(chooser, message);
        this.message = message;
    }

    @Override
    public final void prepare() {
        prepareHttpsMessageContents();
    }

    protected abstract void prepareHttpsMessageContents();

}
