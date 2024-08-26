<?php
// Include the database connection file
require 'db_conn.php';

// Handle registration
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['register'])) {
    $reg_user = $_POST['reg_username'];
    $reg_email = $_POST['reg_email'];
    $reg_pass = $_POST['reg_password'];
    
    // Hash the password
    $hashed_pass = password_hash($reg_pass, PASSWORD_BCRYPT);
    
    // Prepare and bind
    $stmt = $conn->prepare("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $reg_user, $reg_email, $hashed_pass);
    
    // Execute the statement
    if ($stmt->execute()) {
        $reg_message = "Registration successful!";
    } else {
        $reg_message = "Error: " . $stmt->error;
    }
    
    $stmt->close();
}

// Handle login
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['login'])) {
    $login_user = $_POST['login_username'];
    $login_pass = $_POST['login_password'];
    
    // Determine if input is an email or username
    $column = filter_var($login_user, FILTER_VALIDATE_EMAIL) ? 'email' : 'username';
    
    // Prepare and execute
    $stmt = $conn->prepare("SELECT password_hash FROM users WHERE $column = ?");
    $stmt->bind_param("s", $login_user);
    $stmt->execute();
    $stmt->store_result();
    
    if ($stmt->num_rows > 0) {
        $stmt->bind_result($password_hash);
        $stmt->fetch();
        
        // Verify the password
        if (password_verify($login_pass, $password_hash)) {
            $login_message = "Login successful!";
        } else {
            $login_message = "Invalid username or password.";
        }
    } else {
        $login_message = "Invalid username or password.";
    }
    
    $stmt->close();
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Index Page</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .container {
            display: flex;
            justify-content: space-between;
            width: 60%;
            max-width: 1000px;
        }
        .form-container {
            width: 45%;
            padding: 20px;
            border: 1px solid #ccc;
            border-radius: 5px;
        }
        .form-container h2 {
            margin-top: 0;
        }
        .form-container input {
            width: 100%;
            padding: 10px;
            margin: 5px 0;
            border: 1px solid #ddd;
            border-radius: 5px;
        }
        .form-container input[type="submit"] {
            background-color: #4CAF50;
            color: white;
            border: none;
        }
        .form-container input[type="submit"]:hover {
            background-color: #45a049;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Registration Form -->
        <div class="form-container">
            <h2>Register</h2>
            <form method="post" action="">
                <label for="reg_username">Username:</label>
                <input type="text" id="reg_username" name="reg_username" required>
                <br>
                <label for="reg_email">Email:</label>
                <input type="email" id="reg_email" name="reg_email" required>
                <br>
                <label for="reg_password">Password:</label>
                <input type="password" id="reg_password" name="reg_password" required>
                <br>
                <input type="submit" name="register" value="Register">
            </form>
            <?php if (isset($reg_message)) echo "<p>$reg_message</p>"; ?>
        </div>

        <!-- Login Form -->
        <div class="form-container">
            <h2>Login</h2>
            <form method="post" action="">
                <label for="login_username">Username or Email:</label>
                <input type="text" id="login_username" name="login_username" required>
                <br>
                <label for="login_password">Password:</label>
                <input type="password" id="login_password" name="login_password" required>
                <br>
                <input type="submit" name="login" value="Login">
            </form>
            <?php if (isset($login_message)) echo "<p>$login_message</p>"; ?>
        </div>
    </div>
</body>
</html>
