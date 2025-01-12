import React, { useState } from "react";

const Signup = () => {
    const [email, setEmail] = useState("");

    const handleSubmit = async (e) => {
        e.preventDefault();
        console.log("Signup data:", { email });
        // Add signup API call here
        const signupData = {email};
  
        try {
            const response = await fetch("http://127.0.0.1:5000/signup/", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(signupData),
            });
    
            if (response.ok) {
                const result = await response.json();
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
            <h2>Signup</h2>
            <form onSubmit={handleSubmit}>
                <label>Email:</label>
                <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    placeholder="Enter your email"
                />
                <button type="submit">Signup</button>
            </form>
        </div>
    );
};

export default Signup;
