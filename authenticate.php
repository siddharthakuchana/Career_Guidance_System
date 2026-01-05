<?php
include 'config.php'; // Include database connection

session_start();

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = trim($_POST['username']);
    $password = trim($_POST['password']);

    // Validate input fields
    if (empty($username) || empty($password)) {
        echo "<script>alert('Please enter both username and password.'); window.location='login.php';</script>";
        exit();
    }

    // Prepare SQL query to check user by username
    $query = "SELECT id, username, email, password, role FROM users WHERE username = ?";
    $stmt = mysqli_prepare($conn, $query);
    mysqli_stmt_bind_param($stmt, "s", $username);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_store_result($stmt);

    if (mysqli_stmt_num_rows($stmt) > 0) {
        mysqli_stmt_bind_result($stmt, $user_id, $username, $email, $hashed_password, $role);
        mysqli_stmt_fetch($stmt);

        // Verify password
        if (password_verify($password, $hashed_password)) {
            // Authentication successful - Store session data
            $_SESSION['user_id'] = $user_id;
            $_SESSION['username'] = $username;
            $_SESSION['email'] = $email;
            $_SESSION['role'] = $role;
            header("Location: index.php"); // Redirect to index after login
            exit();
        } else {
            echo "<script>alert('Invalid username or password.'); window.location='login.php';</script>";
        }
    } else {
        echo "<script>alert('User not found.'); window.location='login.php';</script>";
    }

    mysqli_stmt_close($stmt);
}
?>