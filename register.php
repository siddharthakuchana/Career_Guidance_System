<?php
include 'config.php'; // Include database connection

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = password_hash(trim($_POST['password']), PASSWORD_BCRYPT); // Hash password

    // Validate input fields
    if (empty($username) || empty($email) || empty($_POST['password'])) {
        echo "<script>alert('Please fill in all fields.'); window.location='signup.php';</script>";
        exit();
    }

    // Check if username or email already exists
    $check_query = "SELECT * FROM users WHERE username = ? OR email = ?";
    $stmt = mysqli_prepare($conn, $check_query);
    mysqli_stmt_bind_param($stmt, "ss", $username, $email);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_store_result($stmt);

    if (mysqli_stmt_num_rows($stmt) > 0) {
        // Account already exists
        echo "<script>alert('Account already exists! Please log in.'); window.location='login.php';</script>";
    } else {
        // Insert new user into database
        $insert_query = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)";
        $insert_stmt = mysqli_prepare($conn, $insert_query);
        mysqli_stmt_bind_param($insert_stmt, "sss", $username, $email, $password);
        if (mysqli_stmt_execute($insert_stmt)) {
            echo "<script>alert('Account created successfully! You can now log in.'); window.location='login.php';</script>";
        } else {
            echo "<script>alert('Error creating account! Try again.'); window.location='signup.php';</script>";
        }
        mysqli_stmt_close($insert_stmt);
    }
    mysqli_stmt_close($stmt);
}
?>