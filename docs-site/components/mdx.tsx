import defaultMdxComponents from 'fumadocs-ui/mdx';
import { Callout } from 'fumadocs-ui/components/callout';
import { Card, Cards } from 'fumadocs-ui/components/card';
import { Step, Steps } from 'fumadocs-ui/components/steps';
import { Tab, Tabs } from 'fumadocs-ui/components/tabs';
import type { MDXComponents } from 'mdx/types';
import type { ReactNode } from 'react';

function Info({ children }: { children: ReactNode }) {
  return <Callout type="info">{children}</Callout>;
}

function Warning({ children }: { children: ReactNode }) {
  return <Callout type="warn">{children}</Callout>;
}

function DocStep({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <Step>
      {title ? <h3>{title}</h3> : null}
      {children}
    </Step>
  );
}

function DocCard({ title, href, children }: { title: string; href?: string; icon?: string; children?: ReactNode }) {
  return (
    <Card title={title} href={href}>
      {children}
    </Card>
  );
}

export function getMDXComponents(components?: MDXComponents) {
  return {
    ...defaultMdxComponents,
    Callout,
    Info,
    Warning,
    Steps,
    Step: DocStep,
    Card: DocCard,
    Cards,
    Tab,
    Tabs,
    ...components,
  } satisfies MDXComponents;
}

export const useMDXComponents = getMDXComponents;

declare global {
  type MDXProvidedComponents = ReturnType<typeof getMDXComponents>;
}
