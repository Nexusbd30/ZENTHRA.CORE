import React from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import DashboardLayout from "./layouts/DashboardLayout";
import PrivateRoute from "./modules/auth/PrivateRoute";
import Navbar from "./components/Navbar";
import Sidebar from "./components/Sidebar";
import AppRouter from "./routes/AppRouter";

const authState = vi.hoisted(() => ({
  user: { email: "admin.ops@vaelqorix.ai", role: "admin" },
  loading: false,
  backendOffline: false,
  logout: vi.fn(),
}));
const notify = vi.hoisted(() => vi.fn());

vi.mock("@/hooks/useAuth", () => ({
  useAuth: () => authState,
}));
vi.mock("@/hooks/useNotification", () => ({
  useNotification: () => ({ notify }),
}));
vi.mock("@/components/NotificationProvider", () => ({
  useNotify: () => notify,
}));

function renderAt(ui, route = "/dashboard") {
  return render(<MemoryRouter initialEntries={[route]}>{ui}</MemoryRouter>);
}

describe("shell and routing coverage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.setItem("access_token", "token");
    authState.user = { email: "admin.ops@vaelqorix.ai", role: "admin" };
    authState.loading = false;
    authState.backendOffline = false;
  });

  it("covers private route loading, blocked, children, element and null branches", () => {
    authState.loading = true;
    const { unmount } = renderAt(<PrivateRoute>private content</PrivateRoute>);
    expect(screen.getByText(/Verificando/)).toBeInTheDocument();
    unmount();

    authState.loading = false;
    authState.user = null;
    renderAt(
      <Routes>
        <Route path="/dashboard" element={<PrivateRoute>blocked content</PrivateRoute>} />
        <Route path="/login" element={<div>login target</div>} />
      </Routes>
    );
    expect(screen.getByText("login target")).toBeInTheDocument();

    authState.user = { email: "admin.ops@vaelqorix.ai", role: "admin" };
    const child = renderAt(<PrivateRoute><div>child content</div></PrivateRoute>);
    expect(screen.getByText("child content")).toBeInTheDocument();
    child.unmount();

    const element = renderAt(<PrivateRoute element={<div>element content</div>} />);
    expect(screen.getByText("element content")).toBeInTheDocument();
    element.unmount();

    const empty = renderAt(<PrivateRoute />);
    expect(empty.container.textContent).toBe("");
  });

  it("covers navbar and sidebar logout flows", () => {
    renderAt(
      <Routes>
        <Route path="/" element={<div>home target</div>} />
        <Route path="/login" element={<div>login target</div>} />
        <Route path="/dashboard" element={<><Navbar /><Sidebar /></>} />
      </Routes>
    );

    expect(screen.getByText("Panel Principal")).toBeInTheDocument();
    expect(screen.getByText("admin.ops@vaelqorix.ai")).toBeInTheDocument();
    fireEvent.click(screen.getAllByText("Cerrar sesión")[0]);
    expect(authState.logout).toHaveBeenCalled();
    expect(notify).toHaveBeenCalled();
    expect(screen.getByText("home target")).toBeInTheDocument();
  });

  it("covers dashboard layout online, offline, mobile drawer and diagnostics navigation", () => {
    authState.backendOffline = true;
    renderAt(
      <Routes>
        <Route path="/dashboard" element={<DashboardLayout />}>
          <Route index element={<div>dashboard outlet</div>} />
          <Route path="diagnostics" element={<div>diagnostics target</div>} />
        </Route>
        <Route path="/login" element={<div>login target</div>} />
      </Routes>
    );

    expect(screen.getByText("Centro de mando")).toBeInTheDocument();
    expect(screen.getAllByText("Offline").length).toBeGreaterThan(0);
    expect(screen.getByText(/Backend offline/)).toBeInTheDocument();
    fireEvent.click(screen.getByLabelText("Abrir navegacion"));
    fireEvent.click(screen.getAllByLabelText("Cerrar navegacion")[1]);
    fireEvent.click(screen.getByLabelText("Abrir navegacion"));
    fireEvent.click(screen.getAllByLabelText("Cerrar navegacion")[0]);
    fireEvent.click(screen.getAllByText("Diagnostico")[0]);
    expect(screen.getByText("diagnostics target")).toBeInTheDocument();
    fireEvent.click(screen.getByText("Cerrar sesion"));
    expect(authState.logout).toHaveBeenCalled();
    expect(notify).toHaveBeenCalledWith("warning", "Sesion cerrada correctamente.");
    expect(screen.getByText("login target")).toBeInTheDocument();
  });

  it("covers AppRouter loading, public, private and fallback routes", () => {
    authState.loading = true;
    const loading = renderAt(<AppRouter />, "/login");
    expect(screen.getByText(/Cargando|Loading|Inicializando/i)).toBeInTheDocument();
    loading.unmount();

    authState.loading = false;
    authState.user = null;
    const login = renderAt(<AppRouter />, "/login");
    expect(document.body.textContent).toMatch(/Initialize Handshake|VAELQORIX/i);
    login.unmount();

    const fallback = renderAt(<AppRouter />, "/missing");
    expect(document.body.textContent).toMatch(/VAELQORIX|Command/i);
    fallback.unmount();

    authState.user = { email: "admin.ops@vaelqorix.ai", role: "admin" };
    const dashboard = renderAt(<AppRouter />, "/dashboard");
    expect(document.body.textContent).toMatch(/Centro de mando|Resumen/i);
    dashboard.unmount();
  });
});
