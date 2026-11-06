/**
 * Section heading used across redone pages: a mono section mark and label,
 * a restrained title, and an optional one-paragraph note.
 */
export function SectionHead({
  mark,
  label,
  title,
  body,
}: {
  mark: string;
  label: string;
  title: string;
  body?: string;
}) {
  return (
    <div className="mb-8">
      <div className="text-[13px] text-stone mb-3">
        <span className="text-mist mr-2">{mark}</span>
        {label}
      </div>
      <h2 className="text-[26px] md:text-[30px] leading-[1.2] tracking-[-0.015em] font-medium text-ink max-w-[640px] text-balance">
        {title}
      </h2>
      {body && <p className="mt-4 text-[14px] leading-[1.7] text-stone max-w-[560px] text-pretty">{body}</p>}
    </div>
  );
}
