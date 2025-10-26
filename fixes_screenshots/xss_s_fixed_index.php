<?php
// /var/www/html/dvwa/vulnerabilities/xss_s/source/index.php
// Stored XSS — Hardened + Hard sanitizer to prevent popups (for demo)

// ---- Session & cookie params (set secure=>true if using HTTPS) ----
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'domain'   => '',
    'secure'   => false,   // set true on HTTPS
    'httponly' => true,
    'samesite' => 'Lax'
]);
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// ---- Security headers (must be sent before any output) ----
header("Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");

// ---- Helpers ----
function h($s) {
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function gen_csrf_token() {
    if (empty($_SESSION['xss_s_csrf'])) {
        try {
            $_SESSION['xss_s_csrf'] = bin2hex(random_bytes(32));
        } catch (Exception $e) {
            $_SESSION['xss_s_csrf'] = sha1(uniqid('', true));
        }
    }
    return $_SESSION['xss_s_csrf'];
}
function verify_csrf($token) {
    return !empty($token) && !empty($_SESSION['xss_s_csrf']) && hash_equals($_SESSION['xss_s_csrf'], $token);
}

// ----- HARD SANITIZER (aggressively neutralizes scripts & dangerous attributes) -----
function hard_sanitize(string $s): string {
    if ($s === null) return '';

    // 1) Remove any <script ...> ... </script> (case-insensitive, multiline)
    $s = preg_replace('#<script\b[^>]*>(.*?)</script>#is', '', $s);

    // 2) Remove <style> blocks too (optional, prevents CSS-based attacks)
    $s = preg_replace('#<style\b[^>]*>(.*?)</style>#is', '', $s);

    // 3) Neutralize javascript: URIs in href/src attributes by replacing value
    $s = preg_replace_callback(
        '#\s+(href|src)\s*=\s*(["\'])(.*?)\2#is',
        function($m) {
            $attr = strtolower($m[1]);
            $val = $m[3];
            if (preg_match('#^\s*javascript:#i', $val)) {
                return " {$attr}={$m[2]}#disabled_js#{$m[2]}";
            }
            return $m[0];
        },
        $s
    );

    // 4) Remove event handler attributes like onclick="..." (quoted and unquoted)
    $s = preg_replace('#\s+on[a-z]+\s*=\s*(["\'])(.*?)\1#is', '', $s);      // quoted
    $s = preg_replace('#\s+on[a-z]+\s*=\s*[^>\s]+#i', '', $s);             // unquoted

    // 5) Neutralize JS function calls in plain text (alert, prompt, confirm, eval, Function)
    $s = preg_replace_callback('#\b(alert|prompt|confirm|eval|Function)\s*\(#i', function($m){ return $m[1] . '_disabled('; }, $s);

    // 6) Remove <iframe>, <object>, <embed> tags entirely
    $s = preg_replace('#<(iframe|object|embed)\b[^>]*>(.*?)</\1>#is', '', $s);
    $s = preg_replace('#<(iframe|object|embed)\b[^>]*\/?>#is', '', $s);

    // 7) Final encode everything (escape any remaining tags)
    $s = htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

    // 8) Convert newlines to <br> for display
    $s = nl2br($s);

    return $s;
}
// ----- END hard sanitizer -----

// ---- Init vars ----
$errors = [];
$notice = '';
$csrf_token = gen_csrf_token();

// ---- Handle POST (store comment) ----
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $posted = $_POST;
    $token = isset($posted['csrf_token']) ? $posted['csrf_token'] : '';

    if (!verify_csrf($token)) {
        $errors[] = 'Invalid CSRF token.';
    } else {
        // sanitize and limit input length
        $raw_name    = isset($posted['name']) ? (string)$posted['name'] : '';
        $raw_comment = isset($posted['comment']) ? (string)$posted['comment'] : '';

        $name = substr(trim($raw_name), 0, 100);
        $comment = substr(trim($raw_comment), 0, 3000);

        // remove control chars
        $name = preg_replace('/[\x00-\x1F\x7F]/u', '', $name);
        $comment = preg_replace('/[\x00-\x1F\x7F]/u', '', $comment);

        if ($name === '') { $errors[] = 'Name is required.'; }
        if ($comment === '') { $errors[] = 'Comment is required.'; }

        if (empty($errors)) {
            $insert_ok = false;
            // MySQLi path
            $link = $GLOBALS["___mysqli_ston"] ?? null;
            if ($link) {
                $stmt = mysqli_prepare($link, "INSERT INTO posts (name, comment) VALUES (?, ?)");
                if ($stmt !== false) {
                    mysqli_stmt_bind_param($stmt, "ss", $name, $comment);
                    if (!mysqli_stmt_execute($stmt)) {
                        error_log("xss_s hard: mysqli_stmt_execute failed: " . mysqli_stmt_error($stmt));
                        $errors[] = 'Database insert failed.';
                    } else {
                        $insert_ok = true;
                    }
                    mysqli_stmt_close($stmt);
                } else {
                    error_log("xss_s hard: mysqli_prepare failed: " . mysqli_error($link));
                    $errors[] = 'Database error.';
                }
            } else {
                // SQLite path
                global $sqlite_db_connection;
                if (isset($sqlite_db_connection) && $sqlite_db_connection) {
                    $stmt = $sqlite_db_connection->prepare('INSERT INTO posts (name, comment) VALUES (:name, :comment)');
                    if ($stmt === false) {
                        error_log('xss_s hard: SQLite prepare failed: ' . $sqlite_db_connection->lastErrorMsg());
                        $errors[] = 'Database error.';
                    } else {
                        $stmt->bindValue(':name', $name, SQLITE3_TEXT);
                        $stmt->bindValue(':comment', $comment, SQLITE3_TEXT);
                        $res = $stmt->execute();
                        if ($res === false) {
                            error_log('xss_s hard: SQLite execute failed: ' . $sqlite_db_connection->lastErrorMsg());
                            $errors[] = 'Database insert failed.';
                        } else {
                            $insert_ok = true;
                        }
                        if (method_exists($stmt, 'close')) { $stmt->close(); }
                    }
                } else {
                    $errors[] = 'No database connection.';
                }
            }

            if ($insert_ok) {
                $notice = 'Comment posted successfully.';
                // rotate token to reduce replay risk
                unset($_SESSION['xss_s_csrf']);
                $csrf_token = gen_csrf_token();
            }
        }
    }
}

// ---- Read posts safely and apply hard sanitizer on output ----
$posts_html = '';
$rows = [];
$link = $GLOBALS["___mysqli_ston"] ?? null;
if ($link) {
    $res = mysqli_query($link, "SELECT id, name, comment, created_at FROM posts ORDER BY id DESC LIMIT 100");
    if ($res !== false) {
        while ($r = mysqli_fetch_assoc($res)) { $rows[] = $r; }
        mysqli_free_result($res);
    }
} else {
    global $sqlite_db_connection;
    if (isset($sqlite_db_connection) && $sqlite_db_connection) {
        $results = $sqlite_db_connection->query('SELECT id, name, comment, created_at FROM posts ORDER BY id DESC LIMIT 100;');
        if ($results !== false) {
            while ($r = $results->fetchArray(SQLITE3_ASSOC)) { $rows[] = $r; }
        }
    }
}

// Build HTML with strict escaping + hard_sanitize for comments
foreach ($rows as $row) {
    $rid = isset($row['id']) ? (int)$row['id'] : 0;
    $rname = isset($row['name']) ? $row['name'] : '';
    $rcomm = isset($row['comment']) ? $row['comment'] : '';
    $rtime = isset($row['created_at']) ? $row['created_at'] : '';

    $name_safe = h($rname);
    // First apply hard sanitizer to neutralize scripts & attributes, then escape, then nl2br is already applied in hard_sanitize
    $comm_sanitized = hard_sanitize($rcomm);

    $time_safe = h($rtime);

    $posts_html .= '<div class="post">';
    $posts_html .= '<div class="meta">#' . $rid . ' &middot; ' . $name_safe;
    if ($time_safe !== '') { $posts_html .= ' &middot; ' . $time_safe; }
    $posts_html .= '</div>';
    $posts_html .= '<div class="comment">' . $comm_sanitized . '</div>';
    $posts_html .= '</div>';
}

?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>DVWA — Stored XSS (Hardened, No Popups)</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{font-family:Arial,Helvetica,sans-serif;margin:20px;color:#222}
.container{max-width:900px;margin:0 auto}
.form-card{background:#f6f8fa;padding:12px;border:1px solid #ddd;margin-bottom:16px}
.input{width:100%;padding:8px;margin:6px 0;box-sizing:border-box}
.button{padding:8px 12px}
.post{border-bottom:1px dashed #ddd;padding:8px 0}
.post .meta{color:#666;font-size:0.9em;margin-bottom:6px}
.post .comment{white-space:pre-wrap}
.notice{background:#e6ffed;border-left:4px solid #2d9c4b;padding:8px;margin-bottom:8px}
.error{background:#ffecec;border-left:4px solid #d9534f;padding:8px;margin-bottom:8px}
</style>
</head>
<body>
<div class="container">
    <h1>Stored XSS — Hardened (No popups)</h1>

    <?php if (!empty($notice)): ?>
        <div class="notice"><?php echo h($notice); ?></div>
    <?php endif; ?>

    <?php if (!empty($errors)): ?>
        <div class="error"><ul><?php foreach ($errors as $e) { echo '<li>' . h($e) . '</li>'; } ?></ul></div>
    <?php endif; ?>

    <div class="form-card">
        <form method="post" action="">
            <label for="name">Name (max 100 chars)</label>
            <input id="name" class="input" name="name" maxlength="100" type="text" value="" required>

            <label for="comment">Comment (max 3000 chars)</label>
            <textarea id="comment" class="input" name="comment" rows="6" maxlength="3000" required></textarea>

            <input type="hidden" name="csrf_token" value="<?php echo h($csrf_token); ?>">

            <button type="submit" class="button">Post</button>
        </form>
    </div>

    <h2>Recent posts</h2>
    <div id="posts">
        <?php
            if ($posts_html === '') {
                echo '<p>No posts yet.</p>';
            } else {
                echo $posts_html;
            }
        ?>
    </div>

    <hr>
    <p style="font-size:0.9em;color:#666">This page aggressively neutralizes potentially dangerous content and always encodes output. For production-grade HTML allowance use a trusted sanitizer (HTMLPurifier) and context-aware output encoding.</p>
</div>
</body>
</html>
