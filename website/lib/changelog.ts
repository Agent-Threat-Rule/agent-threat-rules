import { readFileSync } from "node:fs";
import { join } from "node:path";

export interface ChangelogSection {
  heading: string;
  items: string[];
}

export interface ChangelogEntry {
  version: string;
  date: string;
  sections: ChangelogSection[];
}

/** Heading for blockquote notes added under a version after release. */
const NOTE_HEADING = "Notice";

/**
 * Parses CHANGELOG.md at build time. Format expected:
 *
 *   ## [VERSION] - YYYY-MM-DD
 *   > Optional note added later, e.g. a withdrawn figure (one or more paragraphs)
 *   ### SectionName
 *   - item1
 *   - item2 (may continue on next indented line)
 *
 * Blockquote notes become a "Notice" section placed first in their entry, so a
 * withdrawn figure is never shown on the site without its note.
 *
 * Returns entries in file order (newest first, per Keep-a-Changelog convention).
 */
export function loadChangelog(): ChangelogEntry[] {
  let raw: string;
  try {
    raw = readFileSync(join(process.cwd(), "..", "CHANGELOG.md"), "utf-8");
  } catch {
    return [];
  }
  const lines = raw.split("\n");
  const entries: ChangelogEntry[] = [];
  let currentEntry: ChangelogEntry | null = null;
  let currentSection: ChangelogSection | null = null;
  let currentItem: string | null = null;
  let currentNote: string | null = null;

  const flushItem = () => {
    if (currentItem !== null && currentSection) {
      currentSection.items.push(currentItem.trim());
    }
    currentItem = null;
  };

  const flushNote = () => {
    if (currentNote !== null && currentEntry && currentNote.trim() !== "") {
      let note = currentEntry.sections.find((s) => s.heading === NOTE_HEADING);
      if (!note) {
        note = { heading: NOTE_HEADING, items: [] };
        currentEntry.sections.unshift(note);
      }
      note.items.push(currentNote.trim());
    }
    currentNote = null;
  };

  for (const line of lines) {
    const versionMatch = line.match(/^##\s+\[([^\]]+)\]\s*(?:-\s*(.+))?$/);
    const sectionMatch = line.match(/^###\s+(.+)$/);
    const bulletMatch = line.match(/^-\s+(.+)$/);
    const continuationMatch = line.match(/^\s{2,}(\S.*)$/);
    const quoteMatch = line.match(/^>\s?(.*)$/);

    if (quoteMatch && currentEntry) {
      flushItem();
      const text = quoteMatch[1].trim();
      if (text === "") {
        flushNote();
      } else {
        currentNote = currentNote === null ? text : `${currentNote} ${text}`;
      }
      continue;
    }
    flushNote();

    if (versionMatch) {
      flushItem();
      if (currentEntry) entries.push(currentEntry);
      currentEntry = {
        version: versionMatch[1],
        date: (versionMatch[2] || "").trim(),
        sections: [],
      };
      currentSection = null;
    } else if (sectionMatch && currentEntry) {
      flushItem();
      currentSection = { heading: sectionMatch[1].trim(), items: [] };
      currentEntry.sections.push(currentSection);
    } else if (bulletMatch && currentSection) {
      flushItem();
      currentItem = bulletMatch[1];
    } else if (continuationMatch && currentItem !== null) {
      currentItem += " " + continuationMatch[1];
    } else if (line.trim() === "" && currentItem !== null) {
      flushItem();
    }
  }
  flushItem();
  flushNote();
  if (currentEntry) entries.push(currentEntry);
  return entries;
}
