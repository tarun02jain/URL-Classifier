import React, { useState } from "react";

const App = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [result, setResult] = useState("");
  const [error, setError] = useState("");

  const handleLogin = (e) => {
    e.preventDefault();

    fetch("http://127.0.0.1:5000/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ email, password }),
    })
      .then((res) => {
        if (!res.ok) {
          throw new Error("Invalid credentials");
        }
        return res.json();
      })
      .then(() => {
        setIsLoggedIn(true);
        setError("");
      })
      .catch((err) => {
        console.error(err);
        setError("Login failed. Please check your credentials.");
      });
  };

  const handleCheckURL = () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const url = tabs[0]?.url;
      console.log("Current Tab URL:", url);

      fetch("http://127.0.0.1:5000/extract_features_and_predict/", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url }),
      })
        .then((res) => {
          if (!res.ok) {
            throw new Error("Error fetching prediction");
          }
          return res.json();
        })
        .then((data) => {
          if (data.predictions === 1) {
            setResult("Possibly Phished");
          } else {
            setResult("Legit");
          }
        })
        .catch((err) => {
          console.error(err);
          setError("Error checking the URL.");
        });
    });
  };

  return (
    <div style={{ padding: "16px", fontFamily: "Arial, sans-serif" }}>
      <h2>URL Classifier</h2>
      {isLoggedIn ? (
        <div>
          <p>Logged in as: {email}</p>
          <button onClick={handleCheckURL}>Check Current URL</button>
          {result && <p>Result: {result}</p>}
          {error && <p style={{ color: "red" }}>{error}</p>}
        </div>
      ) : (
        <form onSubmit={handleLogin}>
          <div>
            <label>
              Email:
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </label>
          </div>
          <div>
            <label>
              Password:
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </label>
          </div>
          <button type="submit">Login</button>
          {error && <p style={{ color: "red" }}>{error}</p>}
        </form>
      )}
    </div>
  );
};

export default App;
