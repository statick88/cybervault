/**
 * Plus Admin UI - Main App Component
 */

import { BrowserRouter, Routes, Route } from "react-router-dom";
import { Layout } from "./components/Layout";
import { Dashboard } from "./pages/Dashboard";
import { Resources } from "./pages/Resources";
import { Users } from "./pages/Users";
import { Matrix } from "./pages/Matrix";
import { Policies } from "./pages/Policies";
import { Challenges } from "./pages/Challenges";
import { Audit } from "./pages/Audit";
import { Settings } from "./pages/Settings";

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="resources" element={<Resources />} />
          <Route path="users" element={<Users />} />
          <Route path="matrix" element={<Matrix />} />
          <Route path="policies" element={<Policies />} />
          <Route path="challenges" element={<Challenges />} />
          <Route path="audit" element={<Audit />} />
          <Route path="settings" element={<Settings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}