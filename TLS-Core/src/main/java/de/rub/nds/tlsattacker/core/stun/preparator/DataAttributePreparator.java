package de.rub.nds.tlsattacker.core.stun.preparator;

import de.rub.nds.tlsattacker.core.stun.model.DataAttribute;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class DataAttributePreparator extends StunAttributePreparator<DataAttribute> {

    public DataAttributePreparator(Chooser chooser, DataAttribute attribute) {
        super(chooser, attribute);
    }

    @Override
    public void prepareContent() {
        byte[] data;
        if(getObject().getDataConfig() == null) {
            data = getObject().getDataConfig();
        }else{
            data = chooser.getIceChooser().getConfig().getDefaultData();
        }
        getObject().setData(data);
    }
    
}
