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

public class InspectUseGunRTTI extends BN_JKScript {

    private String hexDelta(int value) {
        if (value < 0) {
            return String.format("-0x%02X", Math.abs(value));
        }
        return String.format("+0x%02X", value);
    }

    public void run() throws Exception {

        PrintWriter out = new PrintWriter(
            "/root/BN_JK-analysis/output/usegun_rtti.txt"
        );

        try {

            Address base = toAddr(0x1004aa570L);

            Memory mem = currentProgram.getMemory();
            Listing listing = currentProgram.getListing();
            FunctionManager fm = currentProgram.getFunctionManager();
            ReferenceManager rm = currentProgram.getReferenceManager();

            out.println("BASE=" + base);
            out.println("IMAGE_BASE=" + currentProgram.getImageBase());
            out.println();

            out.println("=== AROUND RTTI ===");

            for (int off = -0x80; off <= 0x100; off += 8) {

                Address slot;

                try {
                    slot = base.add(off);
                } catch (Exception e) {
                    continue;
                }

                long raw;

                try {
                    raw = mem.getLong(slot);
                } catch (Exception e) {
                    continue;
                }

                Address ptr;

                try {
                    ptr = toAddr(raw);
                } catch (Exception e) {
                    continue;
                }

                out.print(
                    hexDelta(off) + " " +
                    slot + " -> " + ptr
                );

                MemoryBlock b = mem.getBlock(ptr);

                if (b != null) {

                    out.print(
                        " [" + b.getName() +
                        " R=" + b.isRead() +
                        " W=" + b.isWrite() +
                        " X=" + b.isExecute() + "]"
                    );

                    Function f = fm.getFunctionContaining(ptr);

                    if (f != null) {
                        out.print(
                            " FUNCTION=" +
                            f.getEntryPoint() +
                            "|" +
                            f.getName()
                        );
                    }

                    try {
                        Data d = listing.getDataAt(ptr);

                        if (d != null) {
                            out.print(" DATA=" + d);
                        }
                    } catch (Exception ignored) {
                    }
                }

                out.println();
            }

            out.println();
            out.println("=== REFERENCES TO EACH SLOT ===");

            for (int off = -0x40; off <= 0x60; off += 8) {

                Address slot;

                try {
                    slot = base.add(off);
                } catch (Exception e) {
                    continue;
                }

                ReferenceIterator refs;

                try {
                    refs = rm.getReferencesTo(slot);
                } catch (Exception e) {
                    continue;
                }

                boolean printed = false;

                while (refs.hasNext()) {

                    if (!printed) {
                        out.println(
                            "SLOT=" + slot +
                            " DELTA=" + hexDelta(off)
                        );
                        printed = true;
                    }

                    Reference r = refs.next();

                    out.println(
                        "  FROM=" +
                        r.getFromAddress() +
                        " TYPE=" +
                        r.getReferenceType()
                    );

                    Function f =
                        fm.getFunctionContaining(r.getFromAddress());

                    if (f != null) {
                        out.println(
                            "    FUNCTION=" +
                            f.getEntryPoint() +
                            "|" +
                            f.getName()
                        );
                    }
                }
            }

            out.println();
            out.println("USEGUN_RTTI_EXPORT_OK");

        } finally {
            out.close();
        }

        println("USEGUN_RTTI_COMPLETE");
    }
}
