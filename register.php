
<?php
if($_SERVER["REQUEST_METHOD"] == "POST"){
    require_once "config.php";

    $username = $_POST['username'];
    $email = $_POST['email'];
    $password = $_POST['password']; // 不加密密碼

    $sql = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)";
    if($stmt = mysqli_prepare($link, $sql)){
        mysqli_stmt_bind_param($stmt, "sss", $param_username, $param_email, $param_password);
        $param_username = $username;
        $param_email = $email;
        $param_password = $password;
        
        if(mysqli_stmt_execute($stmt)){
            echo "註冊成功";
        } else {
            echo "Oops! Something went wrong. Please try again later.";
        }
        mysqli_stmt_close($stmt);
    }
    mysqli_close($link);
}
?>
 /**$password = password_hash($_POST['password'], PASSWORD_DEFAULT);*/