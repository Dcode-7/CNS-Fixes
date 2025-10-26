<?php
// /var/www/html/dvwa/vulnerabilities/xss_r/source/index.php
// Reflected XSS (fixed) - safe output encoding + CSP + HttpOnly cookies

// Defense-in-depth: set secure session cookie params (adjust 'secure' => true when using HTTPS)
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'domain'   => '',             // leave empty to use current host
    'secure'   => false,          // set to true when using HTTPS
    'httponly' => true,
    'samesite' => 'Lax'
]);
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Add security headers (must be sent before any output)
header("Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");

// Helper: safe encode for HTML text context
function h($s) {
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// Get and sanitize input (defense-in-depth)
// We trim, limit length to 200 chars, and do not allow binary garbage.
$raw_name = isset($_GET['name']) ? $_GET['name'] : '';
$raw_name = is_string($raw_name) ? $raw_name : '';
$name_trim = substr(trim($raw_name), 0, 200);

// Optionally: further validation (uncomment to enforce)
// if (!preg_match('/^[\p{L}\p{N}\s\.\'\-@]{0,200}$/u', $name_trim)) {
//     $name_trim = '';
// }

// Prepare safe output
$name_safe = h($name_trim);

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <title>DVWA — Reflected XSS (Fixed)</title>
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <style>
        body { font-family: Arial, Helvetica, sans-serif; margin: 24px; color: #222; }
        .box { max-width: 800px; margin: 0 auto; }
        .note { background:#f6f8fa; padding:12px; border-left:4px solid #2b8aef; margin-bottom:16px; }
        label { display:block; margin-bottom:6px; font-weight:600; }
        input[type="text"] { width:100%; padding:8px; box-sizing:border-box; margin-bottom:8px; }
        pre { background:#111; color:#fff; padding:12px; overflow:auto; }
    </style>
</head>
<body>
<div class="box">
    <h1>Reflected XSS — Safe Example</h1>

    <div class="note">
        <strong>Fixed:</strong> user input is <em>encoded on output</em> so scripts cannot execute.
        Content-Security-Policy and HttpOnly session cookies are also enabled for defense-in-depth.
    </div>

    <form method="get" action="">
        <label for="name">Enter name (try a script tag to confirm it is sanitized):</label>
        <input id="name" name="name" type="text" value="<?php echo $name_safe; ?>" placeholder="e.g. Alice" />
        <button type="submit">Submit</button>
    </form>

    <hr/>

    <h2>Result</h2>

    <?php if ($name_trim !== ''): ?>
        <p>Safe rendering of user-supplied input (HTML-encoded):</p>
        <pre><?php echo $name_safe; ?></pre>

        <p>Explanation:</p>
        <ul>
            <li>The raw input was <code><?php echo h($raw_name); ?></code>.</li>
            <li>Displayed output is HTML-encoded so any tags show as text (no script will run).</li>
            <li>Example: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code> will appear as text, not execute.</li>
        </ul>

        <div class="note">
            <strong>Cookie visibility:</strong>
            <p>Because the session cookie is set with <code>HttpOnly</code>, client-side JavaScript cannot read the session cookie via <code>document.cookie</code>. This prevents many cookie-theft attacks made possible by XSS.</p>
        </div>
    <?php else: ?>
        <p>No name provided. Try submitting the form above to see the safe output.</p>
    <?php endif; ?>

    <hr/>
    <p style="font-size:0.9em;color:#666">Notes for your report: to demonstrate the original impact you can show a screenshot of the vulnerable page executing <code>alert('XSS')</code>. For remediation evidence include this patched file, a screenshot showing the encoded output, and HTTP response headers that show CSP and cookie settings.</p>
</div>
</body>
</html>
