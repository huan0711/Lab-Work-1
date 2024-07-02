<?php
// session 15
$session_duration = 15 * 60;

session_set_cookie_params($session_duration);
session_start();
// 是否登入
if (!isset($_SESSION['username'])) {
    header("location: index.php");
    exit;
}
require_once "config.php";

$message = isset($_SESSION['message']) ? $_SESSION['message'] : '';
$error = isset($_SESSION['error']) ? $_SESSION['error'] : '';

// 清除session訊息
unset($_SESSION['message']);
unset($_SESSION['error']);

// 登出
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['action']) && $_POST['action'] == 'logout') 
{
    $_SESSION = array();
    
    // 刪除session cookie
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }

    // 銷毀session
    session_destroy();

    // 重新導向到登入頁面
    header("location: index.php");
    exit;
}

// 新增留言
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['action']) && $_POST['action'] == 'add')
{
    $content = $_POST['content'];
    $user_id = $_SESSION['id'];
    
    $file_paths = array();
    $uploadOk = 1;
    $error = '';

    // 檔案上傳
    if (!empty($_FILES["fileToUpload"]["name"][0])) 
    {
        $target_dir = "uploads/";

        for ($i = 0; $i < count($_FILES["fileToUpload"]["name"]); $i++) 
        {
            $target_file = $target_dir . basename($_FILES["fileToUpload"]["name"][$i]);
            $fileType = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));

            // 檢查檔案是否存在
            if (file_exists($target_file)) 
            {
                $error .= "檔案已存在: " . $_FILES["fileToUpload"]["name"][$i] . "<br>";
                $uploadOk = 0;
            }

            // 檔案大小
            if ($_FILES["fileToUpload"]["size"][$i] > 5000000) 
            {
                $error .= "檔案過大: " . $_FILES["fileToUpload"]["name"][$i] . "<br>";
                $uploadOk = 0;
            }

            // 檔案格式
            if ($fileType != "jpg" && $fileType != "png" && $fileType != "jpeg" && $fileType != "pdf"&& $fileType != "doc" && $fileType != "docx"&& $fileType != "pptx") 
            {
                $error .= "僅允許 JPG, JPEG, PNG, PDF, DOC & DOCX,PPT 檔案格式: " . $_FILES["fileToUpload"]["name"][$i] . "<br>";
                $uploadOk = 0;
            }

            // 檢查是否有誤
            if ($uploadOk == 0) 
            {
                $error .= "檔案上傳失敗: " . $_FILES["fileToUpload"]["name"][$i] . "<br>";
                break;
            } else {
                if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"][$i], $target_file)) 
                {
                    $file_paths[] = $target_file;
                } else 
                {
                    $error .= "檔案上傳失敗: " . $_FILES["fileToUpload"]["name"][$i] . "<br>";
                    $uploadOk = 0;
                    break;
                }
            }
        }
    }

    if ($uploadOk) 
    {
        $file_paths_str = implode(",", $file_paths);
        $sql = "INSERT INTO messages (user_id, content, file_path) VALUES (?, ?, ?)";
        if ($stmt = mysqli_prepare($link, $sql))
        {
            mysqli_stmt_bind_param($stmt, "iss", $user_id, $content, $file_paths_str);
            if (mysqli_stmt_execute($stmt)) 
            {
                $_SESSION['message'] = "留言已新增";
            } else {
                $_SESSION['error'] = "留言新增失敗。";
            }
            mysqli_stmt_close($stmt);
        }
    } else 
    {
        $_SESSION['error'] = $error;
    }

    header("location: message.php");
    exit;
}

// 刪留言
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['action']) && $_POST['action'] == 'delete') 
{
    $message_id = $_POST['message_id'];
    $user_id = $_SESSION['id'];

    $sql = "DELETE FROM messages WHERE id = ? AND user_id = ?";
    if ($stmt = mysqli_prepare($link, $sql)) 
    {
        mysqli_stmt_bind_param($stmt, "ii", $message_id, $user_id);
        if (mysqli_stmt_execute($stmt)) {
            $_SESSION['message'] = "留言已刪除";
        } else {
            $_SESSION['error'] = "刪除失敗";
        }
        mysqli_stmt_close($stmt);
    }

    header("location: message.php");
    exit;
}

// 更新留言
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['action']) && $_POST['action'] == 'edit') 
{
    $message_id = $_POST['message_id'];
    $content = $_POST['content'];
    $user_id = $_SESSION['id'];

    $sql = "UPDATE messages SET content = ? WHERE id = ? AND user_id = ?";
    if ($stmt = mysqli_prepare($link, $sql)) 
    {
        mysqli_stmt_bind_param($stmt, "sii", $content, $message_id, $user_id);
        if (mysqli_stmt_execute($stmt)) 
        {
            $_SESSION['message'] = "留言已更新";
        } else {
            $_SESSION['error'] = "留言更新失敗";
        }
        mysqli_stmt_close($stmt);
    }

    header("location: message.php");
    exit;
}

// 抓留言
$sql = "SELECT messages.id, messages.content, messages.file_path, messages.created_at, users.username 
        FROM messages 
        JOIN users ON messages.user_id = users.id 
        ORDER BY messages.created_at DESC";
$result = mysqli_query($link, $sql);

mysqli_close($link);
?>

<!doctype html>
<html>
    <head>
        <meta charset="utf-8">
        <title>Message Board</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css">
        <link rel="stylesheet" href="mes.css">
    </head>
    <body>
        <h1>留言板</h1>
        <form action="message.php" method="post" class="logout-form">
            <input type="hidden" name="action" value="logout">
            <button type="submit" class="logout-button">登出</button>
        </form>
        <?php 
        if (!empty($message)) {
            echo '<div class="alert alert-success">' . $message . '</div>';
        }
        if (!empty($error)) {
            echo '<div class="alert alert-danger">' . $error . '</div>';
        }
        ?>
        <form action="message.php" method="post" enctype="multipart/form-data">
            <input type="hidden" name="action" value="add">

            <textarea name="content" placeholder="新增留言" required></textarea>
            <input type="file" id="fileToUpload" name="fileToUpload[]" multiple>
            <button type="submit">新增</button>
            <br>
        </form>
        <div class="messages">
            <?php while ($row = mysqli_fetch_assoc($result)): ?>
                <div class="message">
                    <p><strong><?php echo htmlspecialchars($row['username']); ?>:</strong> <?php echo htmlspecialchars($row['content']); ?></p>
                    <?php if (!empty($row['file_path'])): ?>
                        <?php 
                        $files = explode(",", $row['file_path']);
                        foreach ($files as $file) 
                        {
                            echo '<p><a href="' . htmlspecialchars($file) . '" download>下載檔案</a></p>';
                        }
                        ?>
                    <?php endif; ?>
                    <p><small><?php echo $row['created_at']; ?></small></p>
                    <?php if ($row['username'] == $_SESSION['username']): ?>
                        <form action="message.php" method="post" class="edit-form">
                            <input type="hidden" name="action" value="edit">
                            <input type="hidden" name="message_id" value="<?php echo $row['id']; ?>">
                            <textarea name="content" required><?php echo htmlspecialchars($row['content']); ?></textarea>
                            <button type="submit" class="edit-button">更新</button>
                        </form>
                        <form action="message.php" method="post" class="delete-form">
                            <input type="hidden" name="action" value="delete">
                            <input type="hidden" name="message_id" value="<?php echo $row['id']; ?>">
                            <button type="submit" class="del-button">刪除</button>
                        </form>
                    <?php endif; ?>
                </div>
            <?php endwhile; ?>
        </div>
    </body>
</html>