import { Fragment, type ReactNode } from "react";

function inlineBold(text: string): ReactNode[] {
  return text.split("**").map((part, i) =>
    i % 2 === 1 ? <strong key={i}>{part}</strong> : <Fragment key={i}>{part}</Fragment>
  );
}

export default function ReportView({ markdown }: { markdown: string }) {
  const lines = markdown.split("\n");
  const blocks: ReactNode[] = [];
  let i = 0;
  let key = 0;

  while (i < lines.length) {
    const line = lines[i];

    if (line.startsWith("```")) {
      const buf: string[] = [];
      i++;
      while (i < lines.length && !lines[i].startsWith("```")) buf.push(lines[i++]);
      i++; // closing fence
      blocks.push(<pre key={key++} className="code">{buf.join("\n")}</pre>);
      continue;
    }
    if (line.startsWith("### ")) {
      blocks.push(<h3 key={key++}>{inlineBold(line.slice(4))}</h3>);
    } else if (line.startsWith("## ")) {
      blocks.push(<h2 key={key++}>{inlineBold(line.slice(3))}</h2>);
    } else if (line.startsWith("# ")) {
      blocks.push(<h1 key={key++}>{inlineBold(line.slice(2))}</h1>);
    } else if (line.startsWith("| ")) {
      const buf: string[] = [];
      while (i < lines.length && lines[i].startsWith("|")) buf.push(lines[i++]);
      blocks.push(<pre key={key++} className="code table">{buf.join("\n")}</pre>);
      continue;
    } else if (line.trim() === "") {
      // skip blank
    } else {
      blocks.push(<p key={key++}>{inlineBold(line)}</p>);
    }
    i++;
  }

  return <div className="report">{blocks}</div>;
}
