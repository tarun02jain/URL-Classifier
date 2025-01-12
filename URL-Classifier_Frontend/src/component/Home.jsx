import React from "react";
import { Link } from "react-router-dom";

const Home = () => {
    return (
        <div>
            <h1>Welcome to the App</h1>
            <Link to="/login">Login</Link>
            <br />
            <Link to="/signup">Signup</Link>
        </div>
    );
};

export default Home;
