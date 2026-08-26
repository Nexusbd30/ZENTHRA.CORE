import logo from "@/assets/logos/vaelqorix-logo.jpeg";

export default function Loader() {
  return (
    <div className="flex h-screen flex-col items-center justify-center bg-[#0b1020] text-[#adc6ff]">
      <img
        src={logo}
        alt="VAELQORIX"
        className="mb-6 h-24 w-24 object-contain drop-shadow-[0_0_18px_rgba(94,231,255,0.45)]"
      />
      <div className="relative mb-4">
        <div className="h-14 w-14 animate-spin rounded-full border-2 border-[#5ee7ff] border-t-transparent" />
        <div className="absolute inset-0 rounded-full bg-[#5ee7ff]/10 blur-lg" />
      </div>
      <p className="font-label text-xs uppercase text-[#8c909f]">Inicializando consola</p>
    </div>
  );
}
