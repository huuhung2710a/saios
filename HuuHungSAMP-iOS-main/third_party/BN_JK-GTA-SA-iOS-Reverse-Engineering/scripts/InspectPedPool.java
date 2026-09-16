//@category BN_JK


// BN_JK Reverse Engineering Research
// Autor e responsável pelo estudo: BN_JK
// Projeto: GTA San Andreas iOS ARM64
// Scripts, metodologia, mapeamentos e conclusões organizados por BN_JK.
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;

import java.io.*;
import java.util.*;

public class InspectPedPool extends BN_JKScript {

    public void run() throws Exception {

        PrintWriter out = new PrintWriter(
            "/root/BN_JK-analysis/output/ped_pool.txt"
        );

        Address pool = toAddr(0x100734fd8L);

        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();
        Memory mem = currentProgram.getMemory();

        out.println("PED_POOL_GLOBAL=" + pool);

        MemoryBlock block = mem.getBlock(pool);
        if (block != null) {
            out.println(
                "BLOCK=" + block.getName() +
                " R=" + block.isRead() +
                " W=" + block.isWrite() +
                " X=" + block.isExecute()
            );
        }

        out.println();
        out.println("=== REFERENCES ===");

        ReferenceIterator refs = rm.getReferencesTo(pool);

        Set<Function> functions = new LinkedHashSet<>();

        while (refs.hasNext()) {

            Reference r = refs.next();

            Address from = r.getFromAddress();

            out.println(
                "FROM=" + from +
                " TYPE=" + r.getReferenceType()
            );

            Function f = fm.getFunctionContaining(from);

            if (f != null) {
                out.println(
                    "  FUNCTION=" +
                    f.getEntryPoint() +
                    "|" +
                    f.getName()
                );

                functions.add(f);
            }

            Instruction ins = listing.getInstructionContaining(from);

            if (ins != null) {

                Instruction p = ins;

                for (int i=0; i<8; i++) {
                    Instruction prev = p.getPrevious();
                    if (prev == null) break;
                    p = prev;
                }

                out.println("  CONTEXT:");

                for (int i=0; i<20 && p != null; i++) {
                    out.println(
                        "    " +
                        p.getAddress() +
                        " | " +
                        p
                    );
                    p = p.getNext();
                }
            }
        }

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        out.println();
        out.println("=== DECOMPILED USERS ===");

        for (Function f : functions) {

            out.println();
            out.println(
                "----------------------------------------"
            );

            out.println(
                "FUNCTION=" +
                f.getEntryPoint() +
                "|" +
                f.getName()
            );

            DecompileResults dr =
                decomp.decompileFunction(f, 120, monitor);

            if (dr.decompileCompleted()) {
                out.println(
                    dr.getDecompiledFunction().getC()
                );
            }
        }

        out.close();

        println("PED_POOL_COMPLETE");
    }
}
