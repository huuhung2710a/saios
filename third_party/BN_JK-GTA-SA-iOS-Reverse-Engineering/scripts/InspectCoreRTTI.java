//@category BN_JK


// BN_JK Reverse Engineering Research
// Autor e responsável pelo estudo: BN_JK
// Projeto: GTA San Andreas iOS ARM64
// Scripts, metodologia, mapeamentos e conclusões organizados por BN_JK.
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

import java.io.*;

public class InspectCoreRTTI extends BN_JKScript {

    static class T {
        String name;
        long typeinfo;
        T(String n, long a) { name=n; typeinfo=a; }
    }

    T[] targets = {
        new T("CPed",       0x1004a74d0L),
        new T("CPlayerPed", 0x1004a8450L),
        new T("CVehicle",   0x1004b4458L)
    };

    public void run() throws Exception {

        PrintWriter out = new PrintWriter(
            "/root/BN_JK-analysis/output/core_rtti.txt"
        );

        Memory mem = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();

        for (T t : targets) {

            Address base = toAddr(t.typeinfo);

            out.println("========================================");
            out.println("CLASS=" + t.name);
            out.println("TYPEINFO=" + base);

            for (int off=0; off<=0x30; off+=8) {

                Address slot = base.add(off);
                long raw;

                try {
                    raw = mem.getLong(slot);
                } catch(Exception e) {
                    continue;
                }

                Address ptr = toAddr(raw);

                out.print(
                    String.format("+0x%02X %s -> %s",
                        off, slot, ptr)
                );

                MemoryBlock b = mem.getBlock(ptr);

                if (b != null) {

                    out.print(
                        " [" + b.getName() + "]"
                    );

                    try {
                        Data d = listing.getDataAt(ptr);
                        if (d != null)
                            out.print(" DATA=" + d);
                    } catch(Exception ignored) {}
                }

                out.println();
            }

            out.println();
        }

        out.close();
        println("CORE_RTTI_COMPLETE");
    }
}
