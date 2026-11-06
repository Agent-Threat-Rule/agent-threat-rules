import type { Metadata } from "next";
import { pageAlternates } from "@/lib/seo";
import { RootRedirect } from "./RootRedirect";

// "/" only forwards to /en, so it points search engines at /en rather than
// standing as a page of its own.
export const metadata: Metadata = {
  alternates: pageAlternates("en", ""),
};

export default function RootPage() {
  return <RootRedirect />;
}
