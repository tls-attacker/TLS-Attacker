#!/usr/bin/env python3

"""Build XmlElement annotations for actions.

Get all *Action.java files from workflow.action package and
return a list of XmlElement annotations.
"""
import os
import glob

exclude_actions = ["SendingAction", "ReceivingAction"]

action_pkg = '../TLS-Core/src/main/java/de/rub/nds/tlsattacker/core/workflow/action/'
actions = glob.glob(os.path.join(action_pkg, '*Action.java'))
actions = [os.path.splitext(os.path.basename(a))[0] for a in actions]
imports = []
elements = []

for action_name in actions:
    if action_name in exclude_actions:
        continue
    imports.append('import de.rub.nds.tlsattacker.core.workflow.action.%s;' % action_name)
    elements.append('@XmlElement(type={0}.class, name="{0}")'.format(action_name))
imports = '\n'.join(imports)
elements = ',\n'.join(elements)

declaration = '''@HoldsModifiableVariable
@XmlElements(value={%s})
private List <TlsAction> tlsActions = new ArrayList<>();
''' % elements

print(imports, '\n')
print(declaration)
