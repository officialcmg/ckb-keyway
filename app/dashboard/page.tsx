import { DashboardHome } from "./home";

export default async function DashboardPage({ searchParams }: { searchParams: Promise<{ screen?: string }> }) {
  const devScreen = process.env.NODE_ENV !== "production" ? (await searchParams).screen : undefined;
  return <DashboardHome devScreen={devScreen} />;
}
