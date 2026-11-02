import { notFound } from "next/navigation";
import { ModalGallery } from "./loader";

export const metadata = { title: "SDK dialogs · development" };

/** DEVELOPMENT ONLY: every SDK dialog in each state (`/dev-modals`). Production builds answer 404. */
export default async function DevModalsPage({ searchParams }: { searchParams: Promise<{ scene?: string; theme?: string }> }) {
  if (process.env.NODE_ENV === "production") notFound();
  const params = await searchParams;
  return <ModalGallery scene={params.scene} theme={params.theme === "dark" ? "dark" : "light"} />;
}
