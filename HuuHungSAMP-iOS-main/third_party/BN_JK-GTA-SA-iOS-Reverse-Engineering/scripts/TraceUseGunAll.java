//@category BN_JK


// BN_JK Reverse Engineering Research
// Autor e responsável pelo estudo: BN_JK
// Projeto: GTA San Andreas iOS ARM64
// Scripts, metodologia, mapeamentos e conclusões organizados por BN_JK.
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;

import java.io.*;
import java.util.*;

public class TraceUseGunAll extends BN_JKScript {

    private long[] targets = {
        0x100486b0dL, // TaskUseGun
        0x100486b18L, // CTaskSimpleUseGun
        0x100468fbaL  // 17CTaskSimpleUseGun (RTTI-like)
    };

    @Override
    public void run() throws Exception {

        PrintWriter out = new PrintWriter(
            "/root/BN_JK-analysis/output/usegun_all_refs.txt"
        );

        Listing listing = currentProgram.getListing();
        ReferenceManager rm = currentProgram.getReferenceManager();
        FunctionManager fm = currentProgram.getFunctionManager();
        Memory mem = currentProgram.getMemory();

        Set<String> uniqueFunctions = new LinkedHashSet<>();

        for (long raw : targets) {

            Address target = toAddr(raw);

            out.println();
            out.println(
                "================================================"
            );
            out.println("TARGET=" + target);

            Data d = listing.getDataAt(target);

            if (d != null) {
                out.println("DATA=" + d);
            }

            ReferenceIterator refs =
                rm.getReferencesTo(target);

            int n = 0;

            while (refs.hasNext()) {

                Reference r = refs.next();
                n++;

                Address from = r.getFromAddress();

                out.println(
                    "REF#" + n +
                    " FROM=" + from +
                    " TYPE=" + r.getReferenceType()
                );

                Function f =
                    fm.getFunctionContaining(from);

                if (f != null) {

                    String id =
                        f.getEntryPoint() +
                        "|" +
                        f.getName();

                    out.println(
                        "  FUNCTION=" + id
                    );

                    uniqueFunctions.add(id);
                }

                MemoryBlock b =
                    mem.getBlock(from);

                if (b != null) {
                    out.println(
                        "  BLOCK=" +
                        b.getName() +
                        " X=" +
                        b.isExecute()
                    );
                }

                CodeUnit cu =
                    listing.getCodeUnitContaining(from);

                if (cu != null) {
                    out.println(
                        "  CODE=" + cu
                    );
                }
            }

            out.println("TOTAL_REFS=" + n);
        }

        out.println();
        out.println("================================================");
        out.println("UNIQUE_FUNCTIONS");

        for (String s : uniqueFunctions) {
            out.println(s);
        }

        out.close();

        println("USEGUN_ALL_COMPLETE");
    }
}
