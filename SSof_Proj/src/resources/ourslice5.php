<?php
$a = $_GET['username'];
echo htmlspecialchars($a, ENT_QUOTES, 'UTF-8');
?>