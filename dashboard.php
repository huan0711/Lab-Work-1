<?php
session_start();
if(!isset($_SESSION['username'])){
    header("location: index.php");
    exit;
}

// 這裡可以加入你的其他 PHP 邏輯，例如獲取用戶信息或操作等

// 示範：獲取用戶名
$username = $_SESSION['username'];
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome, <?php echo $username; ?></title>
</head>
<body>
    <h1>Welcome, <?php echo $username; ?>!</h1>
    <p>This is your dashboard. You can add your content here.</p>
    <a href="logout.php">Logout</a>
</body>
</html>