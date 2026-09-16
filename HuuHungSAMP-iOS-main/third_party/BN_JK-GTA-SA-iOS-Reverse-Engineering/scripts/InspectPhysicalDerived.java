//@category BN_JK


// BN_JK Reverse Engineering Research
// Autor e responsável pelo estudo: BN_JK
// Projeto: GTA San Andreas iOS ARM64
// Scripts, metodologia, mapeamentos e conclusões organizados por BN_JK.
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

import java.io.*;

public class InspectPhysicalDerived extends BN_JKScript {

    long[] targets = {
        0x100160400L, // base de 10040815c
        0x10040815cL, // provável CPhysical ctor

        0x1003ee27cL,
        0x100427b28L,
        0x1003d7d48L,

        0x1004233f8L
    };

    public void run() throws Exception {

        PrintWriter out = new PrintWriter(
            "/root/BN_JK-analysis/output/physical_derived.txt"
        );

        FunctionManager fm =
            currentProgram.getFunctionManager();

        Listing listing =
            currentProgram.getListing();

        DecompInterface decomp =
            new DecompInterface();

        decomp.openProgram(currentProgram);

        for (long raw : targets) {

            Address addr = toAddr(raw);

            Function f = fm.getFunctionAt(addr);

            if (f == null)
                f = fm.getFunctionContaining(addr);

            out.println();
            out.println(
                "================================================"
            );

            out.println("TARGET=" + addr);

            if (f == null) {
                out.println("NOT_FOUND");
                continue;
            }

            out.println("FUNCTION=" + f.getName());
            out.println("ENTRY=" + f.getEntryPoint());
            out.println("BODY=" + f.getBody());

            out.println();
            out.println("=== DECOMPILE ===");

            DecompileResults r =
                decomp.decompileFunction(
                    f,
                    120,
                    monitor
                );

            if (r.decompileCompleted()) {
                out.println(
                    r.getDecompiledFunction().getC()
                );
            } else {
                out.println(
                    "DECOMPILE_FAILED=" +
                    r.getErrorMessage()
                );
            }

            out.println();
            out.println("=== VTABLE WRITES ===");

            InstructionIterator ii =
                listing.getInstructions(
                    f.getBody(),
                    true
                );

            while (ii.hasNext()) {

                Instruction ins = ii.next();

                String txt =
                    ins.toString().toLowerCase();

                if (
                    txt.startsWith("adrp") ||
                    txt.startsWith("add ") ||
                    txt.startsWith("str ")
                ) {
                    out.println(
                        ins.getAddress() +
                        " | " +
                        ins
                    );

                    for (Reference ref :
                            ins.getReferencesFrom()) {

                        out.println(
                            "    REF=" +
                            ref.getToAddress() +
                            " TYPE=" +
                            ref.getReferenceType()
                        );
                    }
                }
            }

            out.println();
            out.println("=== CALLERS ===");

            for (Function caller :
                    f.getCallingFunctions(monitor)) {

                out.println(
                    caller.getEntryPoint() +
                    "|" +
                    caller.getName()
                );
            }

            out.println();
            out.println("=== CALLEES ===");

            for (Function callee :
                    f.getCalledFunctions(monitor)) {

                out.println(
                    callee.getEntryPoint() +
                    "|" +
                    callee.getName()
                );
            }
        }

        out.close();

        println(
            "PHYSICAL_DERIVED_COMPLETE"
        );
    }
}
