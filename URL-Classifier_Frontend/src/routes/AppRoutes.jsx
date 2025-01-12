import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Login from "../component/Login";
import Signup from "../component/Signup";
import Home from "../component/Home";

const AppRoutes = () => {
    return (
        <Router>
            <Routes>
                <Route path="/" element={<Home />} />
                <Route path="/login" element={<Login />} />
                <Route path="/signup" element={<Signup />} />
            </Routes>
        </Router>
    );
};

export default AppRoutes;
