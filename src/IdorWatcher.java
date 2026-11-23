import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * IdorWatcher - 被动式越权（IDOR）观察与验证插件
 *
 * 功能：
 *  1) 被动记录 Proxy 流量，按"路径模板"归一化，聚合同一模板下的不同资源 ID
 *  2) 基于状态码/长度规则标记「疑似越权候选」「存在权限边界」
 *  3) 用身份B的 Cookie 重放选中请求，对比响应，给出越权判定
 *  4) CSV 导出；同时自动落盘到 java.io.tmpdir/idor-watcher.csv
 */
public class IdorWatcher implements BurpExtension {

    private static final Pattern NUM = Pattern.compile("^\\d{1,12}$");
    private static final Pattern HEX = Pattern.compile("^[0-9a-fA-F]{16,}$");
    private static final Pattern UUID = Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    private static final Pattern IDKEY = Pattern.compile("(?i)^(id|uid|user_?id|uuid|guid|no|sid|key|code|cid|pid|oid|rid|tid|item_?id|order_?id|account|user)$");

    private MontoyaApi api;
    private final Map<String, Template> templates = new ConcurrentHashMap<>();
    private final List<Entry> entries = Collections.synchronizedList(new ArrayList<>());
    private final List<Identity> identities = new ArrayList<>();

    private DefaultTableModel model;
    private JLabel status;
    private final String[] COLS = {
            "#", "时间", "方法", "路径模板", "资源ID", "原状态", "原长度",
            "被动标记", "B状态", "B长度", "判定"
    };

    /* ---------------- 内部数据结构 ---------------- */

    private static class Identity {
        final String name;
        final String cookie;
        Identity(String name, String cookie) { this.name = name; this.cookie = cookie; }
    }

    private static class Template {
        final String key;
        final Map<String, Entry> byId = new LinkedHashMap<>();
        Template(String key) { this.key = key; }
    }

    private static class Entry {
        int seq;
        String time;
        String method;
        String templateKey;
        String resourceId;
        short status;
        int length;
        String contentType;
        String host;
        int port;
        boolean secure;
        String rawRequest;
        String bodyHash = "";
        String flag = "单点观测";
        String bStatus = "-";
        String bLength = "-";
        String verdict = "-";
        boolean replayed = false;
        Entry() { }
    }

    /* ---------------- 扩展入口 ---------------- */

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("IdorWatcher (passive IDOR watcher)");

        buildUi();
        api.proxy().registerResponseHandler(new ProxyResponseHandler() {
            @Override
            public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse ir) {
                try {
                    observe(ir.request(), ir);
                } catch (Throwable t) {
                    safeLog("observe failed: " + t);
                }
                return ProxyResponseReceivedAction.continueWith(ir);
            }

            @Override
            public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse ir) {
                return ProxyResponseToBeSentAction.continueWith(ir);
            }
        });

        loadIdentityFromFile();

        api.logging().logToOutput("IdorWatcher loaded. Temp CSV: " + autoCsvPath());
        refreshTable();
    }

    private void loadIdentityFromFile() {
        try {
            File f = new File(System.getProperty("java.io.tmpdir"), "idor-b-cookie.txt");
            if (!f.exists()) return;
            String c = new String(java.nio.file.Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8).trim();
            if (!c.isEmpty()) {
                identities.add(new Identity("B1", c));
                safeLog("identity B preloaded from " + f.getAbsolutePath());
            }
        } catch (Throwable t) {
            safeLog("preload identity failed: " + t);
        }
    }

    private void replayAll() {
        if (identities.isEmpty()) { info("请先设置身份B的 Cookie"); return; }
        int limit = Math.min(entries.size(), 50);
        int done = 0;
        for (int i = 0; i < limit; i++) {
            Entry e = entries.get(i);
            if (e.replayed) continue;
            try {
                HttpRequest original = HttpRequest.httpRequest(ByteArray.byteArray(e.rawRequest));
                HttpService svc = HttpService.httpService(e.host, e.port, e.secure);
                HttpRequest reqB = original.withService(svc).withHeader("Cookie", identities.get(0).cookie);
                HttpRequestResponse rr = api.http().sendRequest(reqB);
                if (rr != null && rr.hasResponse()) {
                    HttpResponse respB = rr.response();
                    e.bStatus = String.valueOf(respB.statusCode());
                    e.bLength = String.valueOf(respB.body().length());
                    e.replayed = true;
                    e.verdict = judge(e, respB);
                    done++;
                }
            } catch (Throwable t) {
                safeLog("replayAll item failed: " + t);
            }
        }
        SwingUtilities.invokeLater(this::refreshTable);
        autoDumpCsv();
        info("批量重放完成：" + done + " 条");
    }

    private void safeLog(String s) {
        try { api.logging().logToOutput(s); } catch (Throwable ignored) { }
    }

    private String autoCsvPath() {
        return System.getProperty("java.io.tmpdir") + File.separator + "idor-watcher.csv";
    }

    /* ---------------- 被动观察与归一化 ---------------- */

    private void observe(HttpRequest req, HttpResponse resp) {
        String path = req.pathWithoutQuery();
        String query = req.query();

        Norm n = normalize(path, query);
        if (n == null || n.resourceId.isEmpty()) return;

        Template tpl = templates.computeIfAbsent(n.templateKey, Template::new);
        if (tpl.byId.containsKey(n.resourceId)) {
            tpl.byId.get(n.resourceId).seq = tpl.byId.get(n.resourceId).seq;
            recomputeFlags(tpl);
            return;
        }

        Entry e = new Entry();
        e.time = new SimpleDateFormat("HH:mm:ss").format(new Date());
        e.method = req.method();
        e.templateKey = n.templateKey;
        e.resourceId = n.resourceId;
        e.status = resp.statusCode();
        e.length = resp.body().length();
        e.contentType = String.valueOf(resp.headerValue("Content-Type"));
        e.host = req.httpService() != null ? req.httpService().host() : "";
        e.port = req.httpService() != null ? req.httpService().port() : 80;
        e.secure = req.httpService() != null && req.httpService().secure();
        e.rawRequest = req.toString();
        e.bodyHash = sha256(resp.body().getBytes());

        tpl.byId.put(n.resourceId, e);
        entries.add(e);
        recomputeFlags(tpl);

        SwingUtilities.invokeLater(this::refreshTable);
        autoDumpCsv();
    }

    private static class Norm {
        String templateKey;
        String resourceId;
    }

    private Norm normalize(String path, String query) {
        if (path == null) return null;
        List<String> ids = new ArrayList<>();
        String[] segs = path.split("/", -1);
        StringBuilder tplPath = new StringBuilder();
        for (String s : segs) {
            if (s.isEmpty()) continue;
            if (NUM.matcher(s).matches() || HEX.matcher(s).matches() || UUID.matcher(s).matches()) {
                ids.add(s);
                tplPath.append("/{id}");
            } else {
                tplPath.append("/").append(s);
            }
        }

        StringBuilder tplQuery = new StringBuilder();
        if (query != null && !query.isEmpty()) {
            List<String> parts = new ArrayList<>(Arrays.asList(query.split("&")));
            Collections.sort(parts);
            for (String p : parts) {
                int eq = p.indexOf('=');
                String k = eq >= 0 ? p.substring(0, eq) : p;
                String v = eq >= 0 ? p.substring(eq + 1) : "";
                if (IDKEY.matcher(k).matches() && v.matches("\\d{1,12}")) {
                    ids.add(v);
                    tplQuery.append(k).append("={id}&");
                } else {
                    tplQuery.append(p).append('&');
                }
            }
        }

        Norm n = new Norm();
        n.templateKey = tplPath.toString() + "?" + tplQuery.toString();
        n.resourceId = String.join("|", ids);
        return n;
    }

    /* ---------------- 被动标记规则 ---------------- */

    private void recomputeFlags(Template tpl) {
        int n = tpl.byId.size();
        int ok = 0, denied = 0;
        int minLen = Integer.MAX_VALUE, maxLen = 0;
        Set<String> hashes = new HashSet<>();
        for (Entry e : tpl.byId.values()) {
            if (e.status >= 200 && e.status < 300) {
                ok++;
                minLen = Math.min(minLen, e.length);
                maxLen = Math.max(maxLen, e.length);
                hashes.add(e.bodyHash);
            } else if (e.status == 401 || e.status == 403 || e.status == 302 || e.status == 303) {
                denied++;
            }
        }

        String flag;
        if (n < 2) {
            flag = "单点观测";
        } else if (denied > 0 && ok > 0) {
            flag = "存在权限边界(有拒绝)";
        } else if (ok >= 2 && hashes.size() == 1) {
            flag = "参数未生效(响应恒等)";
        } else if (ok >= 2) {
            double ratio = minLen == 0 ? 999 : (double) maxLen / (double) minLen;
            if (ratio <= 1.3) {
                flag = "疑似越权候选(多ID均2xx且长度相近)";
            } else {
                flag = "多ID均2xx(长度差异大)";
            }
        } else {
            flag = "无可比数据";
        }
        for (Entry e : tpl.byId.values()) e.flag = flag;
    }

    private static String sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(data);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 8; i++) sb.append(String.format("%02x", d[i]));
            return sb.toString();
        } catch (Throwable t) {
            return "";
        }
    }

    /* ---------------- 身份B重放 ---------------- */

    private void replaySelectedWithIdentityB() {
        int row = table() != null ? table().getSelectedRow() : -1;
        if (row < 0) { info("请先在表格中选中一行"); return; }
        if (identities.isEmpty()) { info("请先设置身份B的 Cookie"); return; }

        Entry e = entries.get(row);
        Identity idb = identities.get(identities.size() - 1);

        try {
            HttpRequest original = HttpRequest.httpRequest(ByteArray.byteArray(e.rawRequest));
            HttpService svc = HttpService.httpService(e.host, e.port, e.secure);
            HttpRequest reqB = original.withService(svc).withHeader("Cookie", idb.cookie);

            HttpRequestResponse rr = api.http().sendRequest(reqB);
            if (rr == null || !rr.hasResponse()) { info("重放无响应"); return; }

            HttpResponse respB = rr.response();
            e.bStatus = String.valueOf(respB.statusCode());
            e.bLength = String.valueOf(respB.body().length());
            e.replayed = true;
            e.verdict = judge(e, respB);

            SwingUtilities.invokeLater(this::refreshTable);
            autoDumpCsv();
            info("重放完成：" + e.verdict);
        } catch (Throwable t) {
            info("重放失败: " + t);
            safeLog("replay failed: " + t);
        }
    }

    private String judge(Entry e, HttpResponse respB) {
        short aStatus = e.status, bStatus = respB.statusCode();
        int aLen = e.length, bLen = respB.body().length();
        boolean aOk = aStatus >= 200 && aStatus < 300;
        boolean bOk = bStatus >= 200 && bStatus < 300;
        boolean bDenied = (bStatus == 401 || bStatus == 403 || bStatus == 302 || bStatus == 303);

        if (aOk && bDenied) return "无越权: 身份B被拒绝(" + bStatus + ")";
        if (!aOk) return "原请求非2xx(A=" + aStatus + ")，跳过";
        if (aOk && bOk) {
            String hB = sha256(respB.body().getBytes());
            if (!e.bodyHash.isEmpty() && e.bodyHash.equals(hB)) {
                return "响应完全一致(参数未生效或公共资源，非越权)";
            }
            double ratio = Math.min(aLen, bLen) == 0 ? 999 : (double) Math.abs(aLen - bLen) / (double) Math.max(aLen, bLen);
            if (ratio <= 0.02) {
                return "响应近似(差异<2%): 疑似越权,需确认资源归属";
            }
            return "两侧响应不同(差异" + String.format("%.1f", ratio * 100) + "%): 需人工判断是否同一资源";
        }
        return "需人工判断(A=" + aStatus + ", B=" + bStatus + ")";
    }

    /* ---------------- UI ---------------- */

    private JTable jtable;

    private JTable table() { return jtable; }

    private void info(String msg) {
        if (status != null) status.setText(msg);
        safeLog("[IdorWatcher] " + msg);
    }

    private void buildUi() {
        model = new DefaultTableModel(COLS, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        jtable = new JTable(model);
        jtable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        int[] widths = {40, 70, 60, 380, 90, 60, 70, 260, 60, 70, 320};
        for (int i = 0; i < widths.length; i++) jtable.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);

        JPanel root = new JPanel(new BorderLayout());

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton btnIdent = new JButton("设置身份B(Cookie)");
        JButton btnReplay = new JButton("用身份B重放选中行");
        JButton btnReplayAll = new JButton("重放全部(身份B)");
        JButton btnExport = new JButton("导出CSV");
        JButton btnClear = new JButton("清空");
        toolbar.add(btnIdent);
        toolbar.add(btnReplay);
        toolbar.add(btnReplayAll);
        toolbar.add(btnExport);
        toolbar.add(btnClear);

        status = new JLabel(" 就绪。浏览目标流量后自动收集。");

        root.add(toolbar, BorderLayout.NORTH);
        root.add(new JScrollPane(jtable), BorderLayout.CENTER);
        root.add(status, BorderLayout.SOUTH);

        btnIdent.addActionListener(ev -> {
            String c = JOptionPane.showInputDialog(root, "粘贴身份B的 Cookie 头内容（不含 'Cookie:' 前缀）:");
            if (c != null && !c.trim().isEmpty()) {
                identities.add(new Identity("B" + (identities.size() + 1), c.trim()));
                info("已设置身份B: B" + identities.size());
            }
        });

        btnReplay.addActionListener(ev -> new Thread(this::replaySelectedWithIdentityB).start());
        btnReplayAll.addActionListener(ev -> new Thread(this::replayAll).start());

        btnExport.addActionListener(ev -> {
            JFileChooser fc = new JFileChooser();
            fc.setSelectedFile(new File("idor-watcher.csv"));
            if (fc.showSaveDialog(root) == JFileChooser.APPROVE_OPTION) {
                try {
                    writeCsv(fc.getSelectedFile().getAbsolutePath());
                    info("已导出: " + fc.getSelectedFile().getAbsolutePath());
                } catch (IOException ex) {
                    info("导出失败: " + ex.getMessage());
                }
            }
        });

        btnClear.addActionListener(ev -> {
            templates.clear();
            entries.clear();
            refreshTable();
            info("已清空");
        });

        api.userInterface().registerSuiteTab("IDOR Watcher", root);
    }

    private void refreshTable() {
        if (model == null) return;
        model.setRowCount(0);
        int i = 0;
        for (Entry e : entries) {
            i++;
            model.addRow(new Object[]{
                    i, e.time, e.method, e.templateKey, e.resourceId,
                    e.status, e.length, e.flag,
                    e.bStatus, e.bLength, e.verdict
            });
        }
        if (status != null) status.setText(" 共 " + entries.size() + " 条观测，模板数 " + templates.size());
    }

    /* ---------------- CSV ---------------- */

    private String csvHeader() {
        return "seq,time,method,template,resource_id,status,length,content_type,flag,identityB_status,identityB_length,verdict\n";
    }

    private String csvLine(Entry e) {
        StringBuilder sb = new StringBuilder();
        sb.append(e.seq).append(',');
        sb.append(q(e.time)).append(',');
        sb.append(q(e.method)).append(',');
        sb.append(q(e.templateKey)).append(',');
        sb.append(q(e.resourceId)).append(',');
        sb.append(e.status).append(',');
        sb.append(e.length).append(',');
        sb.append(q(e.contentType)).append(',');
        sb.append(q(e.flag)).append(',');
        sb.append(q(e.bStatus)).append(',');
        sb.append(q(e.bLength)).append(',');
        sb.append(q(e.verdict)).append('\n');
        return sb.toString();
    }

    private String q(String s) {
        if (s == null) return "\"\"";
        return "\"" + s.replace("\"", "\"\"") + "\"";
    }

    private synchronized void writeCsv(String path) throws IOException {
        try (Writer w = new OutputStreamWriter(new FileOutputStream(path), StandardCharsets.UTF_8)) {
            w.write(csvHeader());
            int i = 0;
            for (Entry e : entries) { e.seq = ++i; w.write(csvLine(e)); }
        }
    }

    private void autoDumpCsv() {
        try {
            int i = 0;
            for (Entry e : entries) e.seq = ++i;
            writeCsv(autoCsvPath());
        } catch (Throwable ignored) { }
    }
}
