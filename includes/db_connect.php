<?php
$host = "localhost";
$user = "root"; // default XAMPP user
$pass = "password";     // default XAMPP password is empty
$db = "mikayla"; 

$conn = new mysqli($host, $user, $pass, $db);

if ($conn->connect_error) {
    die("Connection failed: " .$conn->connect_error);
}
?>