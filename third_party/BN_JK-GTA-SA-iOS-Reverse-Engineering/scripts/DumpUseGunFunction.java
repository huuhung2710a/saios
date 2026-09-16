//@category BN_JK


// BN_JK Reverse Engineering Research
// Autor e responsável pelo estudo: BN_JK
// Projeto: GTA San Andreas iOS ARM64
// Scripts, metodologia, mapeamentos e conclusões organizados por BN_JK.
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

import java.io.*;

public class DumpUseGunFunction extends BN_JKScript {

    public void run() throws Exception {

        PrintWriter out = new PrintWriter(
            "/root/BN_JK-analysis/output/usegun_function.txt"
        );

        Listing listing = currentProgram.getListing();

        Address addr = toAddr(0x100348bbcL);

        Function f = listing.getFunctionContaining(addr);

        if (f == null) {
            out.println("FUNCTION_NOT_FOUND");
            out.close();
            return;
        }

        out.println("FUNCTION=" + f.getName());
        out.println("ENTRY=" + f.getEntryPoint());
        out.println("BODY=" + f.getBody());
        out.println();

        out.println("=== INSTRUCTIONS ===");

        InstructionIterator it =
            listing.getInstructions(f.getBody(), true);

        while (it.hasNext()) {

            Instruction ins = it.next();

            out.println(
                ins.getAddress() +
                " | " +
                ins
            );

            for (Reference r :
                    ins.getReferencesFrom()) {

                out.println(
                    "    REF -> " +
                    r.getToAddress() +
                    " TYPE=" +
                    r.getReferenceType()
                );
            }
        }

        out.println();
        out.println("=== CALLS FROM FUNCTION ===");

        InstructionIterator calls =
            listing.getInstructions(f.getBody(), true);

        while (calls.hasNext()) {

            Instruction ins = calls.next();

            FlowType ft = ins.getFlowType();

            if (ft.isCall()) {

                out.println(
                    "CALLSITE=" +
                    ins.getAddress() +
                    " | " +
                    ins
                );

                for (Reference r :
                        ins.getReferencesFrom()) {

                    Address dest =
                        r.getToAddress();

                    out.print(
                        "    DEST=" + dest
                    );

                    Function target =
                        listing.getFunctionAt(dest);

                    if (target != null) {
                        out.print(
                            " FUNCTION=" +
                            target.getName()
                        );
                    }

                    out.println();
                }
            }
        }

        out.close();

        println("USEGUN_FUNCTION_DUMP_COMPLETE");
    }
}
