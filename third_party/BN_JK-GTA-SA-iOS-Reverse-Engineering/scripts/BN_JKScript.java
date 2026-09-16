//@category BN_JK

// BN_JK Reverse Engineering Research
// Autor e responsável pelo estudo: BN_JK
// Camada base dos scripts BN_JK. A referência técnica abaixo é somente uma
// dependência de execução da API de análise e não representa autoria do estudo.

import ghidra.app.script.GhidraScript;

public abstract class BN_JKScript extends GhidraScript {
    protected final String bnJkWorkspace() {
        return "/root/BN_JK-analysis";
    }
}
