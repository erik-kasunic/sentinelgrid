import { useServerFn } from "@tanstack/react-start";
import { useEffect, useState } from "react";
import { toast } from "sonner";

import {
  createFolder,
  listFolders,
  moveInvestigation,
  type CaseFolder,
} from "@/lib/investigations.functions";

const NEW = "__new__";

/** Select that files a saved case into a folder (or creates a new one). */
export function FolderPicker({
  caseId,
  value,
  onMoved,
}: {
  caseId: string;
  value?: string | null;
  onMoved?: (folderId: string | null) => void;
}) {
  const list = useServerFn(listFolders);
  const create = useServerFn(createFolder);
  const move = useServerFn(moveInvestigation);
  const [folders, setFolders] = useState<CaseFolder[]>([]);
  const [current, setCurrent] = useState<string>(value ?? "");

  useEffect(() => {
    void list().then((r) => setFolders(r.folders));
  }, [list]);
  useEffect(() => setCurrent(value ?? ""), [value]);

  const onChange = async (next: string) => {
    let folderId: string | null = next || null;
    if (next === NEW) {
      const name = window.prompt("Folder name (e.g. Incident #1042)")?.trim();
      if (!name) return;
      const res = await create({ data: { name } });
      if (!res.ok) return void toast.error(res.error);
      setFolders((f) =>
        [...f, { ...res.folder, count: 0 }].sort((a, b) => a.name.localeCompare(b.name)),
      );
      folderId = res.folder.id;
    }
    const res = await move({ data: { id: caseId, folderId } });
    if (!res.ok) return void toast.error(res.error);
    setCurrent(folderId ?? "");
    onMoved?.(folderId);
    toast.success(
      folderId
        ? `Filed in ${folders.find((f) => f.id === folderId)?.name ?? "new folder"}.`
        : "Moved to Unfiled.",
    );
  };

  return (
    <select
      aria-label="Case folder"
      value={current}
      onChange={(e) => void onChange(e.target.value)}
      className="h-8 border border-border bg-card px-2 font-mono text-xs text-foreground focus:border-primary focus:outline-none"
    >
      <option value="">Unfiled</option>
      {folders.map((f) => (
        <option key={f.id} value={f.id}>
          {f.name}
        </option>
      ))}
      <option value={NEW}>+ New folder…</option>
    </select>
  );
}
