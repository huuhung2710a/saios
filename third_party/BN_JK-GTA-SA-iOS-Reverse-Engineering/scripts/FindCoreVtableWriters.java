//@category BN_JK


// BN_JK Reverse Engineering Research
// Autor e responsável pelo estudo: BN_JK
// Projeto: GTA San Andreas iOS ARM64
// Scripts, metodologia, mapeamentos e conclusões organizados por BN_JK.
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;

import java.io.*;

public class FindCoreVtableWriters extends BN_JKScript {

    static class T {
        String name;
        long addr;

        T(String n, long a) {
            name = n;
            addr = a;
        }
    }

    T[] targets = {
        new T("CPed_VTABLE_AREA",       0x1004a74f0L),
        new T("CPlayerPed_VTABLE_AREA", 0x1004a8470L),
        new T("CVehicle_VTABLE_AREA",   0x1004b4478L)
    };

    public void run() throws Exception {

        PrintWriter out = new PrintWriter(
            "/root/BN_JK-analysis/output/core_vtable_writers.txt"
        );

        Listing listing = currentProgram.getListing();
        ReferenceManager rm = currentProgram.getReferenceManager();
        FunctionManager fm = currentProgram.getFunctionManager();
        Memory mem = currentProgram.getMemory();

        for (T t : targets) {

            Address target = toAddr(t.addr);

            out.println();
            out.println("================================================");
            out.println("TARGET=" + t.name);
            out.println("ADDR=" + target);

            for (int off = -0x20; off <= 0x60; off += 8) {

                Address slot;

                try {
                    slot = target.add(off);
                } catch(Exception e) {
                    continue;
                }

                out.println(
                    "--- SLOT " +
                    String.format("%s0x%X",
                        off < 0 ? "-" : "+",
                        Math.abs(off)) +
                    " " + slot
                );

                ReferenceIterator refs =
                    rm.getReferencesTo(slot);

                int count = 0;

                while (refs.hasNext()) {

                    Reference r = refs.next();
                    count++;

                    Address from = r.getFromAddress();

                    out.println(
                        "FROM=" + from +
                        " TYPE=" + r.getReferenceType()
                    );

                    Function f =
                        fm.getFunctionContaining(from);

                    if (f != null) {

                        out.println(
                            "  FUNCTION=" +
                            f.getEntryPoint() +
                            "|" +
                            f.getName()
                        );

                        Instruction ins =
                            listing.getInstructionContaining(from);

                        if (ins != null) {

                            Instruction p = ins;

                            for (int i = 0; i < 8; i++) {
                                Instruction prev = p.getPrevious();
                                if (prev == null) break;
                                p = prev;
                            }

                            out.println("  CONTEXT:");

                            for (int i = 0;
                                 i < 18 && p != null;
                                 i++) {

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
                }

                out.println("COUNT=" + count);
            }
        }

        out.close();

        println("CORE_VTABLE_WRITERS_COMPLETE");
    }
}
