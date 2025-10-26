<?php

if (isset($_REQUEST['Submit'])) {

    // Use REQUEST as original code did; but sanitize/validate strictly
    $id = isset($_REQUEST['id']) ? $_REQUEST['id'] : '';

    // initialize html if not already
    if (!isset($html)) { $html = ''; }

    // Strict validation: only digits allowed for user_id
    if (!ctype_digit($id)) {
        $html .= "<pre>No results.</pre>";
    } else {
        // Ensure $id is integer for binding
        $int_id = (int)$id;

        switch ($_DVWA['SQLI_DB']) {

            case MYSQL:
                // MySQL (mysqli) prepared statement
                $link = $GLOBALS["___mysqli_ston"];
                if (!$link) {
                    error_log("MySQL connection missing in low.php");
                    $html .= "<pre>No results.</pre>";
                    break;
                }

                $sql = "SELECT first_name, last_name FROM users WHERE user_id = ? LIMIT 1";

                $stmt = mysqli_prepare($link, $sql);
                if ($stmt === false) {
                    error_log("mysqli_prepare failed: " . mysqli_error($link));
                    $html .= "<pre>No results.</pre>";
                    break;
                }

                mysqli_stmt_bind_param($stmt, 'i', $int_id);

                if (!mysqli_stmt_execute($stmt)) {
                    error_log("mysqli_stmt_execute failed: " . mysqli_stmt_error($stmt));
                    $html .= "<pre>No results.</pre>";
                    mysqli_stmt_close($stmt);
                    break;
                }

                // Try to get result set (get_result may be unavailable)
                $result = mysqli_stmt_get_result($stmt);

                if ($result !== false) {
                    while ($row = mysqli_fetch_assoc($result)) {
                        $first = htmlspecialchars($row['first_name'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
                        $last  = htmlspecialchars($row['last_name'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
                        $html .= "<pre>ID: {$int_id}<br />First name: {$first}<br />Surname: {$last}</pre>";
                    }
                    mysqli_free_result($result);
                } else {
                    // Fallback: bind_result + fetch
                    mysqli_stmt_bind_result($stmt, $first_name_col, $last_name_col);
                    while (mysqli_stmt_fetch($stmt)) {
                        $first = htmlspecialchars($first_name_col, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
                        $last  = htmlspecialchars($last_name_col, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
                        $html .= "<pre>ID: {$int_id}<br />First name: {$first}<br />Surname: {$last}</pre>";
                    }
                }

                mysqli_stmt_close($stmt);
                // Do NOT close global connection here to avoid affecting other pages
                break;

            case SQLITE:
                // SQLite3 prepared statement
                global $sqlite_db_connection;
                if (!isset($sqlite_db_connection) || !$sqlite_db_connection) {
                    error_log("SQLite connection missing in low.php");
                    $html .= "<pre>No results.</pre>";
                    break;
                }

                $stmt = $sqlite_db_connection->prepare('SELECT first_name, last_name FROM users WHERE user_id = :id LIMIT 1;');
                if ($stmt === false) {
                    error_log('SQLite prepare failed: ' . $sqlite_db_connection->lastErrorMsg());
                    $html .= "<pre>No results.</pre>";
                    break;
                }

                $stmt->bindValue(':id', $int_id, SQLITE3_INTEGER);

                $res = $stmt->execute();
                if ($res === false) {
                    error_log('SQLite execute failed: ' . $sqlite_db_connection->lastErrorMsg());
                    $html .= "<pre>No results.</pre>";
                    if (method_exists($stmt, 'close')) { $stmt->close(); }
                    break;
                }

                while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
                    $first = htmlspecialchars($row['first_name'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
                    $last  = htmlspecialchars($row['last_name'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
                    $html .= "<pre>ID: {$int_id}<br />First name: {$first}<br />Surname: {$last}</pre>";
                }

                if (method_exists($stmt, 'close')) { $stmt->close(); }
                break;

            default:
                error_log('Unknown SQLI_DB type in low.php: ' . print_r($_DVWA['SQLI_DB'], true));
                $html .= "<pre>No results.</pre>";
                break;
        } // end switch
    } // end valid id else
} // end Submit check

?>
