import type { Metadata, Viewport } from "next";
import { headers } from "next/headers";
import "./style.css";

const NAME = "chat.";
const DESC = "E2EE";

export async function generateMetadata(): Promise<Metadata> {
  const h = await headers();
  const host = h.get("x-forwarded-host") || h.get("host") || "localhost:1420";
  const local = host.startsWith("localhost") || host.startsWith("127.") || host.startsWith("[::1]");
  const proto = h.get("x-forwarded-proto") || (local ? "http" : "https");
  const base = new URL(proto + "://" + host);
  const img = new URL("/og.png", base).toString();

  return {
    metadataBase: base,
    title: NAME,
    description: DESC,
    applicationName: NAME,
    openGraph: {
      title: NAME,
      description: DESC,
      siteName: NAME,
      url: base.toString(),
      images: [{ url: img, width: 1200, height: 630, alt: NAME }]
    },
    twitter: {
      card: "summary_large_image",
      title: NAME,
      description: DESC,
      images: [img]
    },
    icons: {
      icon: [
        { url: "/favicon-32.png", sizes: "32x32", type: "image/png" },
        { url: "/icon.png", sizes: "512x512", type: "image/png" }
      ],
      apple: [{ url: "/apple-icon.png", sizes: "180x180", type: "image/png" }]
    }
  };
}

export const viewport: Viewport = {
  themeColor: "#0b1220",
  width: "device-width",
  initialScale: 1,
  maximumScale: 1
};

export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}