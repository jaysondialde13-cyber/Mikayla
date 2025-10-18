<?php
// Include database connection
require_once '../includes/db_connect.php';

// Check if form is submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Get and sanitize input values
    $firstname = trim($_POST['firstname']);
    $lastname  = trim($_POST['lastname']);
    $email     = trim($_POST['email']);
    $course    = trim($_POST['course']);
    $username  = trim($_POST['username']);
    $password  = $_POST['password'];

    // Basic validation
    if (empty($firstname) || empty($lastname) || empty($email) || empty($course) || empty($username) || empty($password)) {
        echo "<script>
            alert('Please fill in all fields');
            window.location.href = '../pages/add_user.php';
        </script>";
        exit();
    }

    // Hash the password
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    // Prepare SQL statement
    $stmt = $conn->prepare("INSERT INTO user (firstname, lastname, email, course, username, password) VALUES (?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("ssssss", $firstname, $lastname, $email, $course, $username, $hashed_password);

    // Execute and check
    if ($stmt->execute()) {
        echo "<script>
            alert('User added successfully');
            window.location.href = '../pages/user_list.php';
        </script>";
    } else {
        echo "<script>
            alert('Failed to add user');
            window.location.href = '../pages/user_list.php';
        </script>";
    }

    $stmt->close();
    $conn->close();
} else {
    header("Location: ../add_user.php");
    exit();
}