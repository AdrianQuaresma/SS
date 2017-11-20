<?php
$nis=$_POST['nis'];
$escaped_item = mysql_escape_string($nis);
$query="SELECT *FROM siswa WHERE nis='$escaped_item'";
$q=mysql_query($query,$koneksi);

?>