import { ApplicationPage } from "./application-page";

export default async function DashboardApplicationPage({ params, searchParams }: {
  params: Promise<{ appId: string }>;
  searchParams: Promise<{ screen?: string }>;
}) {
  const { appId } = await params;
  const devScreen = process.env.NODE_ENV !== "production" ? (await searchParams).screen : undefined;
  return <ApplicationPage appId={appId} devScreen={devScreen} />;
}
