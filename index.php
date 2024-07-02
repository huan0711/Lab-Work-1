<?php
// session 15
$session_duration = 15 * 60; // 15 minutes in seconds

session_set_cookie_params($session_duration);
session_start();

if (isset($_SESSION['username'])) 
{
    header("location: message.php");
    exit;
}

require_once "config.php";

$login_err = '';

if ($_SERVER["REQUEST_METHOD"] == "POST") 
{
    if (isset($_POST['action']) && $_POST['action'] == 'login') 
    {
        // 登入
        $username = $_POST['username'];
        $password = $_POST['password'];

        $sql = "SELECT id, username, password FROM users WHERE username = ?";
        if ($stmt = mysqli_prepare($link, $sql)) 
        {
            mysqli_stmt_bind_param($stmt, "s", $param_username);
            $param_username = $username;
            if (mysqli_stmt_execute($stmt)) 
            {
                mysqli_stmt_store_result($stmt);
                if (mysqli_stmt_num_rows($stmt) == 1) 
                {
                    mysqli_stmt_bind_result($stmt, $id, $username, $stored_password);
                    if (mysqli_stmt_fetch($stmt)) 
                    {
                        if ($password == $stored_password) 
                        {
                            $_SESSION['id'] = $id;
                            $_SESSION['username'] = $username;
                            header("location: message.php");
                            exit;
                        } else {
                            $login_err = "Invalid password.";
                            $_SESSION['login_err'] = "帳號或密碼錯誤。";
                        }
                    }
                } else {
                    $login_err = "No account found with that username.";
                    $_SESSION['login_err'] = "帳號或密碼錯誤。";
                }
            } else 
            {
                echo "Oops! Something went wrong. Please try again later.";
            }
            mysqli_stmt_close($stmt);
        }
    } elseif (isset($_POST['action']) && $_POST['action'] == 'register') 
    {
        // 註冊
        $username = $_POST['reg_username'];
        $password = $_POST['reg_password'];
        $confirm_password = $_POST['confirm_password'];

        if ($password != $confirm_password) 
        {
            $register_err = "Passwords do not match.";
        } else 
        {
            $sql = "SELECT id FROM users WHERE username = ?";
            if ($stmt = mysqli_prepare($link, $sql)) 
            {
                mysqli_stmt_bind_param($stmt, "s", $param_username);
                $param_username = $username;

                if (mysqli_stmt_execute($stmt)) 
                {
                    mysqli_stmt_store_result($stmt);
                    if (mysqli_stmt_num_rows($stmt) == 1) 
                    {
                        $register_err = "This username is already taken.";
                    } else 
                    {
                        // 新user
                        $sql = "INSERT INTO users (username, password) VALUES (?, ?)";
                        if ($stmt = mysqli_prepare($link, $sql)) 
                        {
                            mysqli_stmt_bind_param($stmt, "ss", $param_username, $param_password);
                            $param_password = $password;

                            if (mysqli_stmt_execute($stmt)) 
                            {
                                header("location: index.php?success=1");
                                exit;
                            } else 
                            {
                                $register_err = "Something went wrong. Please try again later.";
                            }
                            mysqli_stmt_close($stmt);
                        }
                    }
                } else 
                {
                    echo "Oops! Something went wrong. Please try again later.";
                }
                mysqli_stmt_close($stmt);
            }
        }
    }
}
mysqli_close($link);
?>
<!doctype html>
<html>
<head>
	<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css">
	<link href="switch.css" rel="stylesheet" type="text/css">
	<meta charset="utf-8">
	<title>login</title>
</head>
<body>
<?php if (isset($_GET['success']) && $_GET['success'] == 1): ?>
    <script>
        alert('註冊成功！');
    </script>
<?php endif; ?>
<?php if (isset($_SESSION['login_err'])): ?>
    <script>
        alert('<?php echo $_SESSION['login_err']; unset($_SESSION['login_err']); ?>');
    </script>
<?php endif; ?>
<div class="container" id="container">
	<div class="form-container sign-up-container">
    <form action="index.php" method="post">
			<h1>Create Account</h1>
            <?php 
        if (!empty($register_err)) 
        {
            echo '<div class="alert alert-danger">' . $register_err . '</div>';
        }        
        ?>
			<div class="social-container">
				<a href="https://zh-tw.facebook.com/" class="social"><i class="fab fa-facebook-f"></i></a>
				<a href="https://www.google.com.tw/?hl=zh_TW" class="social"><i class="fab fa-google-plus-g"></i></a>
			</div>
            <span>請輸入用戶名進行註冊</span>
        <input type="text" name="reg_username" placeholder="Username" required />
        <input type="password" name="reg_password" placeholder="Password" required />
        <input type="password" name="confirm_password" placeholder="Confirm Password" required />
        <input type="hidden" name="action" value="register" />
        <button type="submit">Sign Up</button>
		</form>
	</div>
	<div class="form-container sign-in-container">
		<form action="index.php" method="post">
			<h1>Sign in</h1>
			<div class="social-container">
				<a href="https://zh-tw.facebook.com/" class="social"><i class="fab fa-facebook-f"></i></a>
				<a href="https://www.google.com.tw/?hl=zh_TW" class="social"><i class="fab fa-google-plus-g"></i></a>
			</div>
			
			<input type="text" name="username" placeholder="Username" required />
			<input type="password" name="password" placeholder="Password" required />
			<input type="hidden" name="action" value="login" />
			<a href="cant help.html">忘記密碼?</a>
			<button type="submit">Sign In</button>
		</form>
	</div>
	<div class="overlay-container">
		<div class="overlay">
			<div class="overlay-panel overlay-left">
				<h1>Welcome Back!</h1>
				<p>請註冊個人資料以便與我們聯繫<br>Please login with your personal info</p>
				<button class="ghost" id="signIn">Sign In</button>
			</div>
			<div class="overlay-panel overlay-right">
				<h1>Hello, Friend!</h1>
				<p>輸入您的帳號密碼來進行登入<br>Enter your Email and Password</p>
				<button class="ghost" id="signUp">Sign Up</button>
			</div>
		</div>
	</div>
</div>
<div class="footer">
  @2024 MMDB
</div>
	<script src="switch.js"></script>
</body>
</html>