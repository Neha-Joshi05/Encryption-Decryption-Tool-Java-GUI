// ============================================================
// EncryptorApp.java — Desktop Java Swing Encryption Tool
// HOW TO COMPILE: javac EncryptorApp.java
// HOW TO RUN:     java EncryptorApp
// INTERVIEW TIP:  "I used AES-GCM — authenticated encryption
//                  that detects tampering. PBKDF2 derives a
//                  256-bit key from the password + random salt."
// ============================================================

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

public class EncryptorApp extends JFrame {

    // ── UI Components ─────────────────────────────────────────
    private final JTextArea    inArea    = new JTextArea(10, 48);
    private final JTextArea    outArea   = new JTextArea(10, 48);
    private final JPasswordField passField = new JPasswordField(24);
    private final JLabel       status    = new JLabel("  Ready");

    // ── Crypto Parameters ─────────────────────────────────────
    // INTERVIEW TIP: "16-byte salt prevents pre-computed rainbow
    //                 table attacks. 120,000 PBKDF2 iterations
    //                 makes brute force very slow."
    private static final int    SALT_LEN     = 16;
    private static final int    IV_LEN       = 12;
    private static final int    TAG_BITS     = 128;
    private static final int    PBKDF2_ITERS = 120_000;
    private static final int    KEY_BITS     = 256;
    private static final byte[] MAGIC        = {'E','N','C','R'};
    private static final byte   VERSION      = 1;
    private static final SecureRandom RNG    = new SecureRandom();

    // ── Dark Theme Colors ─────────────────────────────────────
    private static final Color BG_DARK    = new Color(13, 17, 23);
    private static final Color BG_CARD    = new Color(22, 27, 34);
    private static final Color ACCENT     = new Color(88, 166, 255);
    private static final Color TEXT_COLOR = new Color(230, 237, 243);
    private static final Color MUTED      = new Color(139, 148, 158);
    private static final Color SUCCESS    = new Color(63, 185, 80);
    private static final Color ERROR_CLR  = new Color(248, 81, 73);

    public EncryptorApp() {
        super("🔐 Encryption / Decryption Tool");

        // Apply dark theme
        applyDarkTheme();

        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        setLayout(new BorderLayout());
        getContentPane().setBackground(BG_DARK);

        add(buildHeader(),  BorderLayout.NORTH);
        add(buildMain(),    BorderLayout.CENTER);
        add(buildStatus(),  BorderLayout.SOUTH);

        setPreferredSize(new Dimension(1000, 720));
        pack();
        setLocationRelativeTo(null);
    }

    private void applyDarkTheme() {
        try {
            UIManager.setLookAndFeel(UIManager.getCrossPlatformLookAndFeelClassName());
        } catch (Exception ignored) {}

        UIManager.put("Panel.background",          BG_DARK);
        UIManager.put("TextArea.background",       BG_CARD);
        UIManager.put("TextArea.foreground",       TEXT_COLOR);
        UIManager.put("TextArea.caretForeground",  ACCENT);
        UIManager.put("TextField.background",      BG_CARD);
        UIManager.put("TextField.foreground",      TEXT_COLOR);
        UIManager.put("PasswordField.background",  BG_CARD);
        UIManager.put("PasswordField.foreground",  TEXT_COLOR);
        UIManager.put("Label.foreground",          TEXT_COLOR);
        UIManager.put("Button.background",         ACCENT);
        UIManager.put("Button.foreground",         BG_DARK);
        UIManager.put("ScrollPane.background",     BG_CARD);
        UIManager.put("ScrollBar.background",      BG_DARK);
    }

    private JPanel buildHeader() {
        JPanel header = new JPanel(new BorderLayout());
        header.setBackground(BG_CARD);
        header.setBorder(new EmptyBorder(16, 24, 16, 24));

        JLabel title = new JLabel("🔐  Encryption / Decryption Tool");
        title.setFont(new Font("Segoe UI", Font.BOLD, 20));
        title.setForeground(TEXT_COLOR);

        JLabel sub = new JLabel("AES-256-GCM  |  PBKDF2 Key Derivation  |  Authenticated Encryption");
        sub.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        sub.setForeground(MUTED);

        JPanel titles = new JPanel();
        titles.setBackground(BG_CARD);
        titles.setLayout(new BoxLayout(titles, BoxLayout.Y_AXIS));
        titles.add(title);
        titles.add(Box.createVerticalStrut(4));
        titles.add(sub);

        header.add(titles, BorderLayout.WEST);
        return header;
    }

    private JPanel buildMain() {
        JPanel root = new JPanel(new GridLayout(1, 2, 16, 0));
        root.setBackground(BG_DARK);
        root.setBorder(new EmptyBorder(16, 16, 16, 16));
        root.add(buildTextPanel());
        root.add(buildFilePanel());
        return root;
    }

    private JPanel buildTextPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(BG_CARD);
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(48, 54, 61)),
            new EmptyBorder(16, 16, 16, 16)
        ));

        // Section title
        JLabel title = new JLabel("Text Encryption / Decryption");
        title.setFont(new Font("Segoe UI", Font.BOLD, 14));
        title.setForeground(ACCENT);
        panel.add(title);
        panel.add(Box.createVerticalStrut(12));

        // Password field
        panel.add(styledLabel("🔑  Password"));
        panel.add(Box.createVerticalStrut(4));
        passField.setBackground(BG_DARK);
        passField.setForeground(TEXT_COLOR);
        passField.setCaretColor(ACCENT);
        passField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(48, 54, 61)),
            new EmptyBorder(8, 10, 8, 10)
        ));
        passField.setFont(new Font("Monospaced", Font.PLAIN, 14));
        panel.add(passField);
        panel.add(Box.createVerticalStrut(14));

        // Input area
        panel.add(styledLabel("📄  Input Text (plaintext or ciphertext)"));
        panel.add(Box.createVerticalStrut(4));
        styleTextArea(inArea);
        panel.add(new JScrollPane(inArea));
        panel.add(Box.createVerticalStrut(14));

        // Output area
        panel.add(styledLabel("🔒  Output"));
        panel.add(Box.createVerticalStrut(4));
        styleTextArea(outArea);
        outArea.setEditable(false);
        panel.add(new JScrollPane(outArea));
        panel.add(Box.createVerticalStrut(14));

        // Buttons
        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        btnRow.setBackground(BG_CARD);
        btnRow.add(styledButton("🔒 Encrypt", SUCCESS,   this::onEncryptText));
        btnRow.add(styledButton("🔓 Decrypt", ACCENT,    this::onDecryptText));
        btnRow.add(styledButton("📋 Copy",    MUTED,     e -> copyToClipboard()));
        btnRow.add(styledButton("🗑️ Clear",   ERROR_CLR, e -> clearAll()));
        panel.add(btnRow);

        return panel;
    }

    private JPanel buildFilePanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(BG_CARD);
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(48, 54, 61)),
            new EmptyBorder(16, 16, 16, 16)
        ));

        JLabel title = new JLabel("File Encryption / Decryption");
        title.setFont(new Font("Segoe UI", Font.BOLD, 14));
        title.setForeground(ACCENT);
        panel.add(title);
        panel.add(Box.createVerticalStrut(16));

        // Encrypt file button
        JButton encFile = styledButton("📂 Select File → Encrypt", SUCCESS, this::onEncryptFile);
        encFile.setAlignmentX(Component.LEFT_ALIGNMENT);
        encFile.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
        panel.add(encFile);
        panel.add(Box.createVerticalStrut(10));

        // Decrypt file button
        JButton decFile = styledButton("📂 Select File → Decrypt", ACCENT, this::onDecryptFile);
        decFile.setAlignmentX(Component.LEFT_ALIGNMENT);
        decFile.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
        panel.add(decFile);
        panel.add(Box.createVerticalStrut(24));

        // Info box
        JTextArea tips = new JTextArea("""
                ℹ️  How it works:

                🔐  Algorithm: AES-256-GCM
                🔑  Key Derivation: PBKDF2 (120,000 iterations)
                🎲  Salt: 16 bytes (random per encryption)
                📦  IV: 12 bytes (random per encryption)
                ✅  Authentication: 128-bit GCM tag

                File output:
                  Encrypt → filename.enc
                  Decrypt → filename.dec

                ⚠️  Use the SAME password to decrypt.
                ⚠️  Wrong password = Authentication Failed.
                ⚠️  Never share your password.
                """);
        tips.setEditable(false);
        tips.setBackground(BG_DARK);
        tips.setForeground(MUTED);
        tips.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        tips.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(48, 54, 61)),
            new EmptyBorder(12, 12, 12, 12)
        ));
        tips.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(tips);

        return panel;
    }

    private JPanel buildStatus() {
        JPanel bar = new JPanel(new BorderLayout());
        bar.setBackground(BG_CARD);
        bar.setBorder(new EmptyBorder(8, 16, 8, 16));
        status.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        status.setForeground(SUCCESS);
        bar.add(status, BorderLayout.WEST);

        JLabel credit = new JLabel("AES-256-GCM | Educational Use  ");
        credit.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        credit.setForeground(MUTED);
        bar.add(credit, BorderLayout.EAST);

        return bar;
    }

    // ── Helpers ───────────────────────────────────────────────
    private JLabel styledLabel(String text) {
        JLabel lbl = new JLabel(text);
        lbl.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        lbl.setForeground(MUTED);
        return lbl;
    }

    private void styleTextArea(JTextArea area) {
        area.setBackground(BG_DARK);
        area.setForeground(TEXT_COLOR);
        area.setCaretColor(ACCENT);
        area.setFont(new Font("Monospaced", Font.PLAIN, 13));
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setBorder(new EmptyBorder(8, 8, 8, 8));
    }

    private JButton styledButton(String label, Color bg, java.awt.event.ActionListener action) {
        JButton btn = new JButton(label);
        btn.addActionListener(action);
        btn.setBackground(bg);
        btn.setForeground(BG_DARK);
        btn.setFont(new Font("Segoe UI", Font.BOLD, 12));
        btn.setBorder(new EmptyBorder(8, 16, 8, 16));
        btn.setFocusPainted(false);
        btn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        return btn;
    }

    // ── Actions ───────────────────────────────────────────────
    private void onEncryptText(ActionEvent e) {
        try {
            String text = inArea.getText();
            char[] pass = passField.getPassword();
            if (text.isEmpty())    { warn("Input text is empty");    return; }
            if (pass.length == 0)  { warn("Password is empty");      return; }
            byte[] packed = encrypt(text.getBytes(StandardCharsets.UTF_8), pass);
            outArea.setText(Base64.getEncoder().encodeToString(packed));
            status("✅  Text encrypted successfully", SUCCESS);
        } catch (Exception ex) {
            error("Encrypt failed: " + ex.getMessage());
        }
    }

    private void onDecryptText(ActionEvent e) {
        try {
            String b64  = inArea.getText().trim();
            char[] pass = passField.getPassword();
            if (b64.isEmpty())    { warn("Input text is empty");    return; }
            if (pass.length == 0) { warn("Password is empty");      return; }
            byte[] packed = Base64.getDecoder().decode(b64);
            byte[] plain  = decrypt(packed, pass);
            outArea.setText(new String(plain, StandardCharsets.UTF_8));
            status("✅  Text decrypted successfully", SUCCESS);
        } catch (IllegalArgumentException ex) {
            error("Input is not valid Base64 encoded ciphertext");
        } catch (GeneralSecurityException ex) {
            error("❌  Authentication failed — wrong password or tampered data");
        } catch (Exception ex) {
            error("Decrypt failed: " + ex.getMessage());
        }
    }

    private void onEncryptFile(ActionEvent e) {
        JFileChooser fc = new JFileChooser();
        if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
        if (passField.getPassword().length == 0) { warn("Password is empty"); return; }
        Path in  = fc.getSelectedFile().toPath();
        Path out = in.resolveSibling(in.getFileName() + ".enc");
        runFileTask("Encrypting file...", () -> {
            byte[] packed = encrypt(Files.readAllBytes(in), passField.getPassword());
            Files.write(out, packed);
            return "✅  Encrypted → " + out.getFileName();
        });
    }

    private void onDecryptFile(ActionEvent e) {
        JFileChooser fc = new JFileChooser();
        if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
        if (passField.getPassword().length == 0) { warn("Password is empty"); return; }
        Path in  = fc.getSelectedFile().toPath();
        String base = in.getFileName().toString();
        String outName = base.endsWith(".enc") ? base.replace(".enc", ".dec") : base + ".dec";
        Path out = in.resolveSibling(outName);
        runFileTask("Decrypting file...", () -> {
            byte[] plain = decrypt(Files.readAllBytes(in), passField.getPassword());
            Files.write(out, plain);
            return "✅  Decrypted → " + out.getFileName();
        });
    }

    private void runFileTask(String msg, Task task) {
        status(msg, MUTED);
        new SwingWorker<String, Void>() {
            @Override protected String doInBackground() throws Exception { return task.run(); }
            @Override protected void done() {
                try { status(get(), SUCCESS); }
                catch (Exception ex) { error("❌  " + ex.getMessage()); }
            }
        }.execute();
    }

    private void copyToClipboard() {
        Toolkit.getDefaultToolkit()
               .getSystemClipboard()
               .setContents(new StringSelection(outArea.getText()), null);
        status("📋  Output copied to clipboard", ACCENT);
    }

    private void clearAll() {
        inArea.setText(""); outArea.setText(""); passField.setText("");
        status("🗑️  Cleared", MUTED);
    }

    private void status(String msg, Color color) {
        status.setText("  " + msg);
        status.setForeground(color);
    }

    private void warn(String m)  {
        JOptionPane.showMessageDialog(this, m, "Notice", JOptionPane.INFORMATION_MESSAGE);
        status("⚠️  " + m, new Color(210, 153, 34));
    }

    private void error(String m) {
        JOptionPane.showMessageDialog(this, m, "Error",  JOptionPane.ERROR_MESSAGE);
        status(m, ERROR_CLR);
    }

    // ── Crypto Core ───────────────────────────────────────────
    private static SecretKey deriveKey(char[] password, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERS, KEY_BITS);
        byte[] keyBytes = SecretKeyFactory
            .getInstance("PBKDF2WithHmacSHA256")
            .generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static byte[] encrypt(byte[] plain, char[] password) throws GeneralSecurityException {
        byte[] salt = new byte[SALT_LEN], iv = new byte[IV_LEN];
        RNG.nextBytes(salt); RNG.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, deriveKey(password, salt), new GCMParameterSpec(TAG_BITS, iv));
        byte[] ct = cipher.doFinal(plain);
        ByteBuffer buf = ByteBuffer.allocate(4 + 1 + 1 + 1 + salt.length + iv.length + ct.length);
        buf.put(MAGIC); buf.put(VERSION);
        buf.put((byte) salt.length); buf.put((byte) iv.length);
        buf.put(salt); buf.put(iv); buf.put(ct);
        return buf.array();
    }

    private static byte[] decrypt(byte[] packed, char[] password)
            throws GeneralSecurityException, IOException {
        ByteBuffer buf = ByteBuffer.wrap(packed);
        byte[] magic = new byte[4]; buf.get(magic);
        if (magic[0]!='E'||magic[1]!='N'||magic[2]!='C'||magic[3]!='R')
            throw new IOException("Bad header — not an encrypted payload");
        if (buf.get() != VERSION) throw new IOException("Unsupported version");
        byte[] salt = new byte[Byte.toUnsignedInt(buf.get())];
        byte[] iv   = new byte[Byte.toUnsignedInt(buf.get())];
        buf.get(salt); buf.get(iv);
        byte[] ct = new byte[buf.remaining()]; buf.get(ct);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, deriveKey(password, salt), new GCMParameterSpec(TAG_BITS, iv));
        return cipher.doFinal(ct);
    }

    @FunctionalInterface
    private interface Task { String run() throws Exception; }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new EncryptorApp().setVisible(true));
    }
}