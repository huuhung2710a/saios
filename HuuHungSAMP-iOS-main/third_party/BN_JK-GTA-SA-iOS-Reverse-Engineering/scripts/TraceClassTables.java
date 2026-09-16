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

public class TraceClassTables extends BN_JKScript {

    private long[] roots = {
        0x1004a6ae8L,
        0x1004a6ba0L,
        0x1004a74d8L,
        0x1004a95f8L,
        0x1004a9610L,

        0x1004aa540L,
        0x1004aa570L,
        0x1004aa588L,
        0x1004aa600L,
        0x1004aa678L
    };

    private PrintWriter out;
    private Listing listing;
    private FunctionManager fm;
    private Memory memory;
    private AddressSpace space;

    @Override
    public void run() throws Exception {

        out = new PrintWriter(new BufferedWriter(
            new FileWriter(
                "/root/BN_JK-analysis/output/class_trace.txt"
            )
        ));

        listing = currentProgram.getListing();
        fm = currentProgram.getFunctionManager();
        memory = currentProgram.getMemory();

        space = currentProgram
            .getAddressFactory()
            .getDefaultAddressSpace();

        out.println("IMAGE_BASE=" + currentProgram.getImageBase());
        out.println();

        for (long rootValue : roots) {

            Address root = space.getAddress(rootValue);

            out.println();
            out.println(
                "============================================================"
            );

            out.println("ROOT=" + root);

            tracePointer(root, 0, new HashSet<String>());
        }

        out.close();

        println("ZONAAPPLE_CLASS_TRACE_COMPLETE");
    }

    private void tracePointer(
        Address addr,
        int depth,
        Set<String> visited
    ) throws Exception {

        if (addr == null)
            return;

        if (depth > 4)
            return;

        String key = addr.toString();

        if (visited.contains(key))
            return;

        visited.add(key);

        MemoryBlock block = memory.getBlock(addr);

        indent(depth);

        out.print("ADDR=" + addr);

        if (block == null) {
            out.println(" BLOCK=NONE");
            return;
        }

        out.print(
            " BLOCK=" + block.getName() +
            " R=" + block.isRead() +
            " W=" + block.isWrite() +
            " X=" + block.isExecute()
        );

        Function f = fm.getFunctionContaining(addr);

        if (f != null) {
            out.print(
                " FUNCTION=" +
                f.getEntryPoint() +
                "|" +
                f.getName()
            );
        }

        out.println();

        if (block.isExecute()) {

            Instruction instruction =
                listing.getInstructionAt(addr);

            if (instruction != null) {

                indent(depth);

                out.println(
                    "CODE=" +
                    instruction.getAddress() +
                    "|" +
                    instruction.toString()
                );
            }

            return;
        }

        for (int off = 0; off < 0x40; off += 8) {

            Address slot;

            try {
                slot = addr.add(off);
            }
            catch (Exception e) {
                continue;
            }

            long value;

            try {
                value = memory.getLong(slot);
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

            MemoryBlock ptrBlock = memory.getBlock(ptr);

            indent(depth);

            out.print(
                "  +" +
                String.format("0x%02X", off) +
                " SLOT=" +
                slot +
                " VALUE=" +
                ptr
            );

            if (ptrBlock == null) {

                out.println(" INVALID");
                continue;
            }

            out.print(
                " -> " +
                ptrBlock.getName() +
                " X=" +
                ptrBlock.isExecute()
            );

            Function pointedFunction =
                fm.getFunctionContaining(ptr);

            if (pointedFunction != null) {

                out.print(
                    " FUNCTION=" +
                    pointedFunction.getEntryPoint() +
                    "|" +
                    pointedFunction.getName()
                );
            }

            out.println();

            if (
                ptrBlock.isExecute() ||
                depth < 3
            ) {
                tracePointer(
                    ptr,
                    depth + 1,
                    new HashSet<String>(visited)
                );
            }
        }
    }

    private void indent(int depth) {

        for (int i = 0; i < depth; i++)
            out.print("    ");
    }
}
