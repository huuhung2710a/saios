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

public class TraceCoreRTTI extends BN_JKScript {

    static class T {
        String name;
        long addr;

        T(String n, long a) {
            name = n;
            addr = a;
        }
    }

    T[] targets = {
        new T("CPed_RTTI",        0x1004a74d0L),
        new T("CPlayerPed_RTTI",  0x1004a8450L),
        new T("CVehicle_RTTI",    0x1004b4458L),

        new T("CPed_TextCandidate",       0x100078664L),
        new T("CPlayerPed_Text1",         0x100275324L),
        new T("CPlayerPed_Text2",         0x100275368L),
        new T("CVehicle_Text1",           0x1004236d4L),
        new T("CVehicle_Text2",           0x1004236d8L)
    };

    public void run() throws Exception {

        PrintWriter out = new PrintWriter(
            "/root/BN_JK-analysis/output/core_rtti_refs.txt"
        );

        ReferenceManager rm = currentProgram.getReferenceManager();
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        Memory mem = currentProgram.getMemory();

        for (T t : targets) {

            Address a = toAddr(t.addr);

            out.println();
            out.println("================================================");
            out.println("TARGET=" + t.name);
            out.println("ADDR=" + a);

            MemoryBlock b = mem.getBlock(a);

            if (b != null) {
                out.println(
                    "BLOCK=" + b.getName() +
                    " R=" + b.isRead() +
                    " W=" + b.isWrite() +
                    " X=" + b.isExecute()
                );
            }

            Function at = fm.getFunctionAt(a);
            Function containing = fm.getFunctionContaining(a);

            if (at != null) {
                out.println(
                    "FUNCTION_AT=" +
                    at.getEntryPoint() +
                    "|" +
                    at.getName()
                );
            }

            if (containing != null) {
                out.println(
                    "FUNCTION_CONTAINING=" +
                    containing.getEntryPoint() +
                    "|" +
                    containing.getName()
                );
            }

            out.println("--- REFERENCES TO ---");

            ReferenceIterator refs = rm.getReferencesTo(a);

            int count = 0;

            while (refs.hasNext()) {

                Reference r = refs.next();
                count++;

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
                }

                CodeUnit cu = listing.getCodeUnitContaining(from);

                if (cu != null) {
                    out.println(
                        "  CODE=" + cu
                    );
                }
            }

            out.println("REF_COUNT=" + count);
        }

        out.close();

        println("CORE_RTTI_REFS_COMPLETE");
    }
}
