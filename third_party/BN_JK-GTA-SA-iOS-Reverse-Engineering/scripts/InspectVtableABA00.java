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

public class InspectVtableABA00 extends BN_JKScript {

    public void run() throws Exception {

        PrintWriter out = new PrintWriter(
            "/root/BN_JK-analysis/output/vtable_aba00.txt"
        );

        Address table = toAddr(0x1004aba00L);

        Memory mem = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();

        out.println("VTABLE=" + table);
        out.println();

        out.println("=== ENTRIES ===");

        for (int off = 0; off < 0x100; off += 8) {

            Address slot = table.add(off);
            long raw;

            try {
                raw = mem.getLong(slot);
            } catch (Exception e) {
                continue;
            }

            Address ptr = toAddr(raw);

            out.print(
                String.format("+0x%02X %s -> %s", off, slot, ptr)
            );

            MemoryBlock b = mem.getBlock(ptr);

            if (b != null) {

                out.print(
                    " [" + b.getName() +
                    " X=" + b.isExecute() + "]"
                );

                Function f = fm.getFunctionContaining(ptr);

                if (f != null) {
                    out.print(
                        " " + f.getEntryPoint() +
                        "|" + f.getName()
                    );
                }
            }

            out.println();
        }

        out.println();
        out.println("=== REFERENCES TO VTABLE ===");

        ReferenceIterator refs = rm.getReferencesTo(table);

        while (refs.hasNext()) {

            Reference r = refs.next();

            Address from = r.getFromAddress();

            out.println(
                from + " TYPE=" + r.getReferenceType()
            );

            Function f = fm.getFunctionContaining(from);

            if (f != null) {
                out.println(
                    "  FUNCTION=" +
                    f.getEntryPoint() +
                    "|" + f.getName()
                );
            }
        }

        out.close();

        println("VTABLE_ABA00_COMPLETE");
    }
}
