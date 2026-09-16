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

public class IdentifyPedDerivedClasses extends BN_JKScript {

    private PrintWriter out;

    private final long[] VTABLES = {
        0x1004a70f8L,
        0x1004a72f8L,
        0x1004a73f8L,
        0x1004a8378L
    };

    private String readStringAt(Address a) {
        try {
            Data d = getDataAt(a);
            if (d != null && d.hasStringValue()) {
                Object v = d.getValue();
                if (v != null)
                    return v.toString();
            }
        }
        catch (Exception e) {
        }

        return null;
    }

    private long readPtr(long address) {
        try {
            Address a = toAddr(address);
            Memory mem = currentProgram.getMemory();
            return mem.getLong(a);
        }
        catch (Exception e) {
            return 0;
        }
    }

    private void dumpAround(long base) {

        out.println("=== AROUND ADDRESS POINT ===");

        for (long off = -0x40; off <= 0x80; off += 8) {

            long slot = base + off;
            long val = readPtr(slot);

            Address va = toAddr(val);

            MemoryBlock block =
                currentProgram.getMemory().getBlock(va);

            String blockName =
                block == null ? "NONE" : block.getName();

            Function f =
                currentProgram.getFunctionManager()
                    .getFunctionAt(va);

            Data d = getDataAt(va);

            out.printf(
                "%+d 0x%X -> 0x%X [%s]",
                off,
                slot,
                val,
                blockName
            );

            if (f != null) {
                out.print(
                    " FUNCTION=" +
                    f.getEntryPoint() +
                    "|" +
                    f.getName()
                );
            }

            if (d != null) {
                out.print(
                    " DATA=" +
                    d.toString()
                );

                if (d.hasStringValue()) {
                    out.print(
                        " STRING=\"" +
                        d.getValue() +
                        "\""
                    );
                }
            }

            out.println();
        }
    }

    private void dumpRefs(long address) {

        out.println("=== REFERENCES TO ADDRESS POINT ===");

        ReferenceManager rm =
            currentProgram.getReferenceManager();

        Address target =
            toAddr(address);

        ReferenceIterator it =
            rm.getReferencesTo(target);

        int count = 0;

        while (it.hasNext()) {

            Reference r =
                it.next();

            count++;

            Address from =
                r.getFromAddress();

            Function f =
                currentProgram.getFunctionManager()
                    .getFunctionContaining(from);

            out.println(
                "FROM=" +
                from +
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

        out.println("REF_COUNT=" + count);
    }

    private void scanBackwardForRTTI(long addressPoint) {

        out.println("=== POSSIBLE RTTI HEADER ===");

        for (long delta = 8; delta <= 0x80; delta += 8) {

            long candidateAddr =
                addressPoint - delta;

            long value =
                readPtr(candidateAddr);

            Address v =
                toAddr(value);

            MemoryBlock block =
                currentProgram.getMemory()
                    .getBlock(v);

            if (block == null)
                continue;

            Data d =
                getDataAt(v);

            if (d != null) {

                String s =
                    readStringAt(v);

                if (s != null) {
                    out.println(
                        "HEADER_SLOT=0x" +
                        Long.toHexString(candidateAddr) +
                        " -> STRING 0x" +
                        Long.toHexString(value) +
                        " = \"" +
                        s +
                        "\""
                    );
                }

                out.println(
                    "HEADER_SLOT=0x" +
                    Long.toHexString(candidateAddr) +
                    " -> 0x" +
                    Long.toHexString(value) +
                    " DATA=" +
                    d
                );
            }
        }
    }

    @Override
    public void run() throws Exception {

        out = new PrintWriter(
            "/root/BN_JK-analysis/output/ped_derived_classes.txt"
        );

        for (long vtable : VTABLES) {

            out.println();
            out.println(
                "================================================"
            );

            out.printf(
                "VTABLE_ADDRESS_POINT=0x%X%n",
                vtable
            );

            dumpAround(vtable);
            scanBackwardForRTTI(vtable);
            dumpRefs(vtable);
        }

        out.close();

        println("PED_DERIVED_CLASSES_COMPLETE");
    }
}
