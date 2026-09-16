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

public class FindTrueCoreVtables extends BN_JKScript {

    static class T {
        String name;
        long rtti;

        T(String n, long r) {
            name = n;
            rtti = r;
        }
    }

    T[] targets = {
        new T("CPed",       0x1004a74d0L),
        new T("CPlayerPed", 0x1004a8450L),
        new T("CVehicle",   0x1004b4458L)
    };

    public void run() throws Exception {

        PrintWriter out = new PrintWriter(
            "/root/BN_JK-analysis/output/true_core_vtables.txt"
        );

        Memory mem = currentProgram.getMemory();
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();

        for (T t : targets) {

            out.println();
            out.println("================================================");
            out.println("CLASS=" + t.name);
            out.println("RTTI=" + toAddr(t.rtti));

            for (MemoryBlock block : mem.getBlocks()) {

                if (!block.isInitialized() || block.isExecute())
                    continue;

                Address p = block.getStart();
                Address end = block.getEnd();

                while (p.compareTo(end) <= 0) {

                    long raw;

                    try {
                        raw = mem.getLong(p);
                    } catch(Exception e) {
                        break;
                    }

                    if (raw == t.rtti) {

                        out.println();
                        out.println("RTTI_POINTER_AT=" + p);
                        out.println("BLOCK=" + block.getName());

                        Address offsetTop = p.subtract(8);
                        Address addressPoint = p.add(8);

                        long topRaw = mem.getLong(offsetTop);

                        out.println(
                            "OFFSET_TO_TOP_AT=" + offsetTop +
                            " VALUE=0x" + Long.toHexString(topRaw)
                        );

                        out.println(
                            "VTABLE_ADDRESS_POINT=" + addressPoint
                        );

                        out.println("--- METHODS ---");

                        for (int off = 0; off < 0x100; off += 8) {

                            Address slot = addressPoint.add(off);
                            long methodRaw;

                            try {
                                methodRaw = mem.getLong(slot);
                            } catch(Exception e) {
                                break;
                            }

                            Address method = toAddr(methodRaw);
                            MemoryBlock mb = mem.getBlock(method);

                            out.print(
                                String.format(
                                    "+0x%02X %s -> %s",
                                    off, slot, method
                                )
                            );

                            if (mb != null) {
                                out.print(
                                    " [" + mb.getName() +
                                    " X=" + mb.isExecute() + "]"
                                );

                                Function f =
                                    fm.getFunctionContaining(method);

                                if (f != null) {
                                    out.print(
                                        " FUNCTION=" +
                                        f.getEntryPoint() +
                                        "|" + f.getName()
                                    );
                                }
                            }

                            out.println();
                        }

                        out.println("--- REFERENCES TO ADDRESS POINT ---");

                        ReferenceIterator refs =
                            rm.getReferencesTo(addressPoint);

                        while (refs.hasNext()) {

                            Reference r = refs.next();

                            out.println(
                                "FROM=" + r.getFromAddress() +
                                " TYPE=" + r.getReferenceType()
                            );

                            Function f =
                                fm.getFunctionContaining(
                                    r.getFromAddress()
                                );

                            if (f != null) {
                                out.println(
                                    "  FUNCTION=" +
                                    f.getEntryPoint() +
                                    "|" + f.getName()
                                );
                            }
                        }
                    }

                    try {
                        p = p.add(8);
                    } catch(Exception e) {
                        break;
                    }
                }
            }
        }

        out.close();
        println("TRUE_CORE_VTABLES_COMPLETE");
    }
}
