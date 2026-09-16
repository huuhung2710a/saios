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

public class DumpPedRTTIChain extends BN_JKScript {

    PrintWriter out;

    long[] targets = {
        0x1004a6fe8L,
        0x1004a70d0L,
        0x1004a71d0L,
        0x1004a72d0L,
        0x1004a73d0L,
        0x1004a74d0L,
        0x1004a8450L
    };

    long readPtr(long a) {
        try {
            return currentProgram.getMemory().getLong(toAddr(a));
        } catch (Exception e) {
            return 0;
        }
    }

    String describe(long a) {

        if (a == 0)
            return "NULL";

        Address addr = toAddr(a);

        MemoryBlock b =
            currentProgram.getMemory().getBlock(addr);

        String block =
            b == null ? "NONE" : b.getName();

        Data d = getDataAt(addr);

        Function f =
            currentProgram.getFunctionManager()
                .getFunctionAt(addr);

        String s =
            String.format("0x%X [%s]", a, block);

        if (d != null) {

            s += " DATA=" + d;

            try {
                if (d.hasStringValue()) {
                    s += " STRING=\"" +
                         d.getValue() + "\"";
                }
            } catch (Exception e) {}
        }

        if (f != null) {
            s += " FUNCTION=" +
                 f.getEntryPoint() +
                 "|" +
                 f.getName();
        }

        return s;
    }

    void dump(long base) {

        out.println();
        out.println(
            "========================================"
        );

        out.printf("TARGET=0x%X%n", base);

        for (long off = -0x20; off <= 0x40; off += 8) {

            long slot = base + off;
            long value = readPtr(slot);

            out.printf(
                "%+d SLOT=0x%X -> %s%n",
                off,
                slot,
                describe(value)
            );
        }

        out.println("--- REFERENCES TO TARGET ---");

        ReferenceIterator it =
            currentProgram.getReferenceManager()
                .getReferencesTo(toAddr(base));

        int n = 0;

        while (it.hasNext()) {

            Reference r = it.next();
            n++;

            Function f =
                currentProgram.getFunctionManager()
                    .getFunctionContaining(
                        r.getFromAddress()
                    );

            out.println(
                "FROM=" +
                r.getFromAddress() +
                " TYPE=" +
                r.getReferenceType()
            );

            if (f != null) {
                out.println(
                    "  FUNCTION=" +
                    f.getEntryPoint() +
                    "|" +
                    f.getName()
                );
            }
        }

        out.println("REF_COUNT=" + n);
    }

    @Override
    public void run() throws Exception {

        out = new PrintWriter(
            "/root/BN_JK-analysis/output/ped_rtti_chain.txt"
        );

        for (long t : targets)
            dump(t);

        out.close();

        println("PED_RTTI_CHAIN_COMPLETE");
    }
}
