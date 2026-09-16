//@category BN_JK


// BN_JK Reverse Engineering Research
// Autor e responsável pelo estudo: BN_JK
// Projeto: GTA San Andreas iOS ARM64
// Scripts, metodologia, mapeamentos e conclusões organizados por BN_JK.
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

import java.io.*;
import java.util.*;

public class MapTaskClasses extends BN_JKScript {

    private Memory mem;
    private Listing listing;
    private FunctionManager fm;
    private AddressSpace space;
    private PrintWriter out;

    private final String[] wanted = {
        "CTaskSimpleUseGun",
        "CTaskSimpleFight",
        "CTaskSimpleThrowProjectile",
        "CTaskSimplePlayerOnFoot",
        "CTaskSimpleSwim",
        "CTaskSimpleDuck",
        "CTaskSimpleJetPack",
        "CTaskComplexPlayerOnFoot",
        "CTaskComplexKillPedOnFoot"
    };

    @Override
    public void run() throws Exception {

        mem = currentProgram.getMemory();
        listing = currentProgram.getListing();
        fm = currentProgram.getFunctionManager();

        space = currentProgram
            .getAddressFactory()
            .getDefaultAddressSpace();

        out = new PrintWriter(
            "/root/BN_JK-analysis/output/task_class_map.txt"
        );

        out.println("IMAGE_BASE=" + currentProgram.getImageBase());
        out.println();

        Map<String, Address> strings = findWantedStrings();

        for (String name : wanted) {

            out.println(
                "============================================================"
            );
            out.println("CLASS=" + name);

            Address str = strings.get(name);

            if (str == null) {
                out.println("STRING=NOT_FOUND");
                continue;
            }

            out.println("STRING=" + str);

            findStructures(name, str);
            out.println();
        }

        out.close();

        println("TASK_CLASS_MAP_COMPLETE");
    }

    private Map<String, Address> findWantedStrings()
        throws Exception {

        Map<String, Address> result =
            new LinkedHashMap<>();

        for (MemoryBlock block : mem.getBlocks()) {

            if (!block.isInitialized())
                continue;

            Address cur = block.getStart();
            Address end = block.getEnd();

            while (cur.compareTo(end) <= 0) {

                String s = readAscii(cur, 128);

                if (s != null) {

                    for (String wantedName : wanted) {

                        if (
                            s.equals(wantedName) &&
                            !result.containsKey(wantedName)
                        ) {
                            result.put(wantedName, cur);
                        }
                    }

                    if (s.length() > 0) {
                        try {
                            cur = cur.add(s.length());
                        }
                        catch (Exception e) {
                            break;
                        }
                    }
                }

                try {
                    cur = cur.add(1);
                }
                catch (Exception e) {
                    break;
                }
            }
        }

        return result;
    }

    private String readAscii(Address a, int max) {

        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < max; i++) {

            byte b;

            try {
                b = mem.getByte(a.add(i));
            }
            catch (Exception e) {
                return null;
            }

            int c = b & 0xff;

            if (c == 0)
                break;

            if (c < 0x20 || c > 0x7e)
                return null;

            sb.append((char)c);
        }

        if (sb.length() < 4)
            return null;

        return sb.toString();
    }

    private void findStructures(
        String className,
        Address stringAddr
    ) throws Exception {

        long target = stringAddr.getOffset();

        for (MemoryBlock block : mem.getBlocks()) {

            if (!block.isInitialized())
                continue;

            if (block.isExecute())
                continue;

            Address p = block.getStart();
            Address end = block.getEnd();

            while (p.compareTo(end) <= 0) {

                long value;

                try {
                    value = mem.getLong(p);
                }
                catch (Exception e) {
                    break;
                }

                if (value == target) {

                    out.println(
                        "STRING_REF=" + p +
                        " BLOCK=" + block.getName()
                    );

                    dumpAround(p);
                }

                try {
                    p = p.add(8);
                }
                catch (Exception e) {
                    break;
                }
            }
        }
    }

    private void dumpAround(Address ref)
        throws Exception {

        for (int delta = -0x20;
             delta <= 0x60;
             delta += 8) {

            Address slot;

            try {
                slot = ref.add(delta);
            }
            catch (Exception e) {
                continue;
            }

            long value;

            try {
                value = mem.getLong(slot);
            }
            catch (Exception e) {
                continue;
            }

            Address ptr;

            try {
                ptr = space.getAddress(value);
            }
            catch (Exception e) {
                continue;
            }

            MemoryBlock targetBlock =
                mem.getBlock(ptr);

            out.print(
                String.format(
                    "  %+04x %s -> %s",
                    delta,
                    slot,
                    ptr
                )
            );

            if (targetBlock != null) {

                out.print(
                    " [" +
                    targetBlock.getName() +
                    "]"
                );

                if (targetBlock.isExecute()) {

                    Function f =
                        fm.getFunctionContaining(ptr);

                    out.print(" EXEC");

                    if (f != null) {
                        out.print(
                            " " +
                            f.getEntryPoint() +
                            "|" +
                            f.getName()
                        );
                    }
                }
            }

            out.println();
        }
    }
}
