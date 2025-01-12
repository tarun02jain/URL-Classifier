import React, { useState } from "react";

const Login = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
  
    const loginData = { email, password };
  
    try {
      // Make the POST request to your server to validate the login
      const response = await fetch("http://127.0.0.1:5000/login/", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(loginData),
      });
  
      if (response.ok) {
        const result = await response.json();
  
        // Send the token to the Chrome extension's background script
        chrome.runtime.sendMessage(
          { type: "STORE_TOKEN", token: result.message },
          (response) => {
            if (response.success) {
              console.log("Token sent to Chrome extension successfully.");
            } else {
              console.error("Failed to send token to Chrome extension.");
            }
          }
        );
  
        console.log("Login successful:", result);
      } else {
        console.error("Login failed:", response.statusText);
      }
    } catch (error) {
      console.error("Error occurred during login:", error);
    }
  };
  

  return (
    <div className="container">
      <h2>Login</h2>
      <form onSubmit={handleSubmit}>
        <label>Email:</label>
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
          placeholder="Enter your email"
        />
        <label>Password:</label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          placeholder="Enter your password"
        />
        <button type="submit">Login</button>
      </form>
    </div>
  );
};

export default Login;
