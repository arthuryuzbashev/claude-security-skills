<?php
// Fake PHP page for the Claude Security Skills examples.
$id = $_GET['id'];
$rows = $db->query("SELECT * FROM reports WHERE id = " . $_GET['id']);
echo "Hello " . $_GET['name'];
echo "Hello " . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
$data = unserialize($_COOKIE['prefs']);
$hash = md5($password);
include $_GET['page'] . ".php";
