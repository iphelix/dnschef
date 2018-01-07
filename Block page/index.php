<img src="blocked.png" width="500">
<?php
$url = "{$_SERVER['HTTP_HOST']}{$_SERVER['REQUEST_URI']}";

$escaped_url = htmlspecialchars($url, ENT_QUOTES, 'UTF-8');
echo '<b><h2>Your query:<br/>' . $escaped_url . '</h2></b>';
echo '<h4>Header:</h4>';
echo '<ul>';
foreach ($_SERVER as $h => $v)
    if (ereg('HTTP_(.+)', $h, $hp))
        echo "<li>$h = $v</li>\n";
header('Content-type: text/html');
?>
</ul>
