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

public class TraceUseGun extends BN_JKScript {

    private PrintWriter out;

    @Override
    public void run() throws Exception {

        out = new PrintWriter(
            "/root/BN_JK-analysis/output/usegun_refs.txt"
        );

        Memory mem = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();
        ReferenceManager rm =
            currentProgram.getReferenceManager();

        Address target =
            toAddr(0x100486b18L);

        out.println("TARGET=" + target);
        out.println("IMAGE_BASE=" +
            currentProgram.getImageBase());
        out.println();

        out.println("=== MEMORY BLOCK ===");

        MemoryBlock tb = mem.getBlock(target);

        if (tb != null) {
            out.println(
                tb.getName() +
                " " +
                tb.getStart() +
                "-" +
                tb.getEnd()
            );
        }

        out.println();
        out.println("=== DATA AT TARGET ===");

        Data d = listing.getDataAt(target);

        if (d != null) {
            out.println(d);
            out.println(
                "TYPE=" +
                d.getDataType().getName()
            );
        } else {
            out.println("NO_DEFINED_DATA");
        }

        out.println();
        out.println("=== REFERENCES TO STRING ===");

        ReferenceIterator refs =
            rm.getReferencesTo(target);

        int count = 0;

        while (refs.hasNext()) {

            Reference r = refs.next();
            count++;

            Address from = r.getFromAddress();

            out.println(
                "REF#" + count +
                " FROM=" + from +
                " TYPE=" +
                r.getReferenceType()
            );

            CodeUnit cu =
                listing.getCodeUnitContaining(from);

            if (cu != null) {
                out.println(
                    "  CODEUNIT=" + cu
                );
            }

            Function f =
                listing.getFunctionContaining(from);

            if (f != null) {
                out.println(
                    "  FUNCTION=" +
                    f.getEntryPoint() +
                    "|" +
                    f.getName()
                );
            }

            MemoryBlock b =
                mem.getBlock(from);

            if (b != null) {
                out.println(
                    "  BLOCK=" +
                    b.getName() +
                    " EXEC=" +
                    b.isExecute()
                );
            }

            dumpInstructions(from);
        }

        out.println();
        out.println("TOTAL_REFS=" + count);

        out.close();

        println("USEGUN_TRACE_COMPLETE");
    }

    private void dumpInstructions(Address center) {

        Listing listing =
            currentProgram.getListing();

        out.println("  --- NEARBY ---");

        Instruction ins =
            listing.getInstructionContaining(center);

        if (ins == null) {
            out.println("  NO_INSTRUCTION");
            return;
        }

        Instruction p = ins;

        for (int i = 0; i < 6; i++) {
            Instruction prev = p.getPrevious();
            if (prev == null)
                break;
            p = prev;
        }

        for (int i = 0;
             i < 14 && p != null;
             i++) {

            out.println(
                "  " +
                p.getAddress() +
                " | " +
                p
            );

            p = p.getNext();
        }
    }
}
