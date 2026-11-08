import Link from "next/link";

export default function NotFound() {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center px-6 text-center">
      <div className="font-data text-[120px] font-bold text-fog leading-none">404</div>
      <p className="text-base text-stone mt-4 mb-6">This page doesn't exist.</p>
      <Link
        href="/en"
        className="bg-ink text-white px-8 py-3 rounded-[2px] text-sm font-semibold hover:bg-black transition-colors"
      >
        Back to ATR
      </Link>
    </div>
  );
}
