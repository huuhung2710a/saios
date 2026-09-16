//@category BN_JK


// BN_JK Reverse Engineering Research
// Autor e responsável pelo estudo: BN_JK
// Projeto: GTA San Andreas iOS ARM64
// Scripts, metodologia, mapeamentos e conclusões organizados por BN_JK.
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

import java.io.*;
import java.util.*;

public class TracePedConstructorPaths extends BN_JKScript {

    private static final long ALLOCATOR       = 0x10023cb7cL;
    private static final long CPED_CTOR       = 0x10023c0a4L;
    private static final long CPLAYERPED_CTOR = 0x10026cb64L;
    private static final long WORLD_ADD       = 0x1001826acL;
    private static final long MODEL_SET       = 0x100141e00L;

    private FunctionManager fm;
    private PrintWriter out;

    private static class PathResult {
        List<Function> path;
        PathResult(List<Function> p) {
            path = p;
        }
    }

    @Override
    public void run() throws Exception {

        fm = currentProgram.getFunctionManager();

        out = new PrintWriter(
            "/root/BN_JK-analysis/output/ped_constructor_paths.txt"
        );

        Function allocatorFn =
            fm.getFunctionAt(toAddr(ALLOCATOR));

        if (allocatorFn == null) {
            out.println("ALLOCATOR_NOT_FOUND");
            out.close();
            return;
        }

        Set<Function> roots =
            allocatorFn.getCallingFunctions(monitor);

        out.println("ALLOCATOR=" + hex(ALLOCATOR));
        out.println("CPED_CTOR=" + hex(CPED_CTOR));
        out.println("CPLAYERPED_CTOR=" + hex(CPLAYERPED_CTOR));
        out.println("ROOT_COUNT=" + roots.size());

        List<Function> sorted =
            new ArrayList<>(roots);

        Collections.sort(sorted, new Comparator<Function>() {
            public int compare(Function a, Function b) {
                return Long.compare(
                    a.getEntryPoint().getOffset(),
                    b.getEntryPoint().getOffset()
                );
            }
        });

        for (Function root : sorted) {

            out.println();
            out.println("================================================");
            out.println(
                "ROOT=" +
                root.getEntryPoint() +
                "|" +
                root.getName()
            );

            boolean world =
                callsDirect(root, WORLD_ADD);

            boolean model =
                callsDirect(root, MODEL_SET);

            out.println("DIRECT_WORLD_ADD=" + world);
            out.println("DIRECT_MODEL_SET=" + model);

            PathResult pedPath =
                findPath(root, CPED_CTOR, 5);

            PathResult playerPath =
                findPath(root, CPLAYERPED_CTOR, 5);

            if (pedPath != null) {
                out.println("PATH_TO_CPED=YES");
                printPath("CPED_PATH", pedPath.path);
            }
            else {
                out.println("PATH_TO_CPED=NO");
            }

            if (playerPath != null) {
                out.println("PATH_TO_CPLAYERPED=YES");
                printPath("CPLAYERPED_PATH", playerPath.path);
            }
            else {
                out.println("PATH_TO_CPLAYERPED=NO");
            }

            out.println("--- DIRECT CALLEES ---");

            List<Function> callees =
                new ArrayList<>(root.getCalledFunctions(monitor));

            Collections.sort(callees, new Comparator<Function>() {
                public int compare(Function a, Function b) {
                    return Long.compare(
                        a.getEntryPoint().getOffset(),
                        b.getEntryPoint().getOffset()
                    );
                }
            });

            for (Function c : callees) {
                out.println(
                    c.getEntryPoint() +
                    "|" +
                    c.getName()
                );
            }
        }

        out.println();
        out.println("================================================");
        out.println("=== FUNCTIONS THAT DIRECTLY CALL CPED CTOR ===");

        Function pedCtor =
            fm.getFunctionAt(toAddr(CPED_CTOR));

        if (pedCtor != null) {
            Set<Function> direct =
                pedCtor.getCallingFunctions(monitor);

            for (Function f : direct) {
                out.println(
                    f.getEntryPoint() +
                    "|" +
                    f.getName()
                );
            }
        }

        out.println();
        out.println(
            "=== DECOMPILE DIRECT CPED-DERIVED CONSTRUCTORS ==="
        );

        if (pedCtor != null) {

            DecompInterface dec =
                new DecompInterface();

            dec.openProgram(currentProgram);

            Set<Function> direct =
                pedCtor.getCallingFunctions(monitor);

            for (Function f : direct) {

                out.println();
                out.println("----------------------------------------");
                out.println(
                    "FUNCTION=" +
                    f.getEntryPoint() +
                    "|" +
                    f.getName()
                );

                DecompileResults dr =
                    dec.decompileFunction(f, 120, monitor);

                if (dr.decompileCompleted()) {
                    out.println(
                        dr.getDecompiledFunction().getC()
                    );
                }
                else {
                    out.println(
                        "DECOMPILE_FAILED=" +
                        dr.getErrorMessage()
                    );
                }

                out.println("--- CALLERS ---");

                for (Function caller :
                        f.getCallingFunctions(monitor)) {

                    out.println(
                        caller.getEntryPoint() +
                        "|" +
                        caller.getName()
                    );
                }

                out.println("--- CALLEES ---");

                for (Function callee :
                        f.getCalledFunctions(monitor)) {

                    out.println(
                        callee.getEntryPoint() +
                        "|" +
                        callee.getName()
                    );
                }
            }
        }

        out.close();

        println("PED_CONSTRUCTOR_PATHS_COMPLETE");
    }

    private boolean callsDirect(Function f, long target) {

        for (Function c :
                f.getCalledFunctions(monitor)) {

            if (c.getEntryPoint().getOffset() == target)
                return true;
        }

        return false;
    }

    private PathResult findPath(
            Function root,
            long target,
            int maxDepth) {

        List<Function> path =
            new ArrayList<>();

        Set<Long> visited =
            new HashSet<>();

        if (dfs(
                root,
                target,
                maxDepth,
                visited,
                path)) {

            return new PathResult(
                new ArrayList<>(path)
            );
        }

        return null;
    }

    private boolean dfs(
            Function current,
            long target,
            int depth,
            Set<Long> visited,
            List<Function> path) {

        if (current == null)
            return false;

        long addr =
            current.getEntryPoint().getOffset();

        if (visited.contains(addr))
            return false;

        visited.add(addr);
        path.add(current);

        if (addr == target)
            return true;

        if (depth <= 0) {
            path.remove(path.size() - 1);
            return false;
        }

        Set<Function> cs =
            current.getCalledFunctions(monitor);

        for (Function c : cs) {

            if (c == null)
                continue;

            Address a =
                c.getEntryPoint();

            if (a == null)
                continue;

            // Limita a funções reais do binário principal.
            if (a.getOffset() < 0x100000000L)
                continue;

            if (dfs(
                    c,
                    target,
                    depth - 1,
                    visited,
                    path)) {

                return true;
            }
        }

        path.remove(path.size() - 1);
        return false;
    }

    private void printPath(
            String label,
            List<Function> path) {

        StringBuilder sb =
            new StringBuilder();

        sb.append(label).append("=");

        for (int i = 0; i < path.size(); i++) {

            if (i != 0)
                sb.append(" -> ");

            Function f =
                path.get(i);

            sb.append(
                f.getEntryPoint()
            );

            sb.append("|");

            sb.append(
                f.getName()
            );
        }

        out.println(sb.toString());
    }

    private String hex(long v) {
        return String.format("0x%X", v);
    }
}
