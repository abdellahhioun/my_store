<?php
$servername = "localhost";
$username = "root"; // Replace with your MySQL username
$password = "";     // Replace with your MySQL password
$dbname = "user_db";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Check if the form was submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $user = $_POST['username'];
    $pass = $_POST['password'];
    
    // Determine if input is an email or username
    $column = filter_var($user, FILTER_VALIDATE_EMAIL) ? 'email' : 'username';
    
    // Prepare and execute
    $stmt = $conn->prepare("SELECT password_hash FROM users WHERE $column = ?");
    $stmt->bind_param("s", $user);
    $stmt->execute();
    $stmt->store_result();
    
    if ($stmt->num_rows > 0) {
        $stmt->bind_result($password_hash);
        $stmt->fetch();
        
        // Verify the password
        if (password_verify($pass, $password_hash)) {
            echo "Login successful!";
        } else {
            echo "Invalid username or password.";
        }
    } else {
        echo "Invalid username or password.";
    }
    
    $stmt->close();
}

$conn->close();
?>

<!-- HTML form for login -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
</head>
<body>
    <h2>Login</h2>
    <form method="post" action="">
        <label for="username">Username or Email:</label>
        <input type="text" id="username" name="username" required>
        <br><br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required>
        <br><br>
        <input type="submit" value="Login">
    </form>
</body>
</html>
