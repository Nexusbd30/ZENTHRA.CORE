import { useNavigate } from "react-router-dom";
import {
  Cpu,
  Brain,
  Network,
  Shield,
  Radio,
  Activity,
  Database,
  Code,
  Layers,
  Lock,
  UserCheck,
  RefreshCw,
} from "lucide-react";
import logo from "../assets/logos/zenthra-logo.png";

export default function Home() {
  const navigate = useNavigate();

  const solutions = [
    { name: "Análisis y Automatización", icon: Cpu },
    { name: "Inteligencia Artificial", icon: Brain },
    { name: "Infraestructura de Red", icon: Network },
    { name: "Seguridad Avanzada", icon: Shield },
    { name: "IoT y Dispositivos", icon: Radio },
    { name: "Monitoreo en Tiempo Real", icon: Activity },
    { name: "Centro de Datos", icon: Database },
    { name: "Software de Control", icon: Code },
    { name: "Arquitectura Digital", icon: Layers },
    { name: "Protección de Amenazas", icon: Lock },
    { name: "Gestión de Identidades", icon: UserCheck },
    { name: "Resiliencia Operativa", icon: RefreshCw },
  ];

  return (
    <div className="min-h-screen bg-gradient-to-b from-[#0f172a] via-[#1e3a8a] to-[#1e40af] text-white flex flex-col items-center relative">
      {/* BOTON ARRIBA IZQUIERDA */}
      <div className="absolute top-6 left-6">
        <button
          onClick={() => navigate("/login")}
          className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg shadow-md tracking-widest uppercase transition-all duration-300 border border-blue-400"
        >
          Acceder al sistema
        </button>
      </div>

      {/* HEADER */}
      <header className="flex items-center justify-center gap-3 mt-16">
        <img
          src={logo}
          alt="ZENTHRA Logo"
          className="w-14 h-14 rounded-lg shadow-neon"
        />
        <h1 className="text-4xl font-bold tracking-wider text-blue-400">
          ZENTHRA.CORE_SECURITY
        </h1>
      </header>

      {/* SUBTITULO */}
      <p className="mt-4 text-blue-200 text-lg tracking-wide text-center max-w-2xl">
        Soluciones avanzadas de monitoreo, análisis e inteligencia cibernética.
        Protege el futuro digital de tu organización.
      </p>

      {/* SECCION PRINCIPAL */}
      <section className="mt-16 text-center w-full flex flex-col items-center">
        <h2 className="text-3xl font-extrabold tracking-widest text-blue-300 mb-10 drop-shadow-lg">
          ZENTHRA SOLUTIONS
        </h2>

        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-6 w-11/12 max-w-6xl">
          {solutions.map((item, index) => (
            <div
              key={index}
              className="bg-blue-500/20 hover:bg-blue-400/30 transition-all border border-blue-300/40 hover:border-blue-200 rounded-xl p-6 text-center cursor-pointer shadow-md hover:shadow-blue-400/50 backdrop-blur-md group"
            >
              <div className="flex flex-col items-center gap-3">
                <item.icon className="w-10 h-10 text-blue-300 group-hover:text-blue-100 transition-all drop-shadow-md" />
                <p className="text-blue-100 font-semibold tracking-wide text-lg">
                  {item.name}
                </p>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* FOOTER */}
      <footer className="mt-16 text-gray-400 text-sm mb-6 tracking-widest">
        © 2025 ZENTHRA SECURITY SYSTEM
      </footer>
    </div>
  );
}

