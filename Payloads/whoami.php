<?php
// simple_whoami.php
header('Content-Type: text/plain');

// try shell_exec first
$output = shell_exec('whoami 2>&1'); //change the command here and do not remove 2>&1

if ($output !== null) {
    echo trim($output) . PHP_EOL;
} else {
    // fallback: try exec
    exec('whoami 2>&1', $lines, $code);
    if (!empty($lines)) {
        echo implode("\n", $lines) . PHP_EOL;
    } else {
        echo "command execution disabled (shell_exec/exec not available)." . PHP_EOL;
    }
}
