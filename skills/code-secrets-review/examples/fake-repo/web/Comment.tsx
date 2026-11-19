// Fake React component for the Claude Security Skills examples.
export function Comment({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
