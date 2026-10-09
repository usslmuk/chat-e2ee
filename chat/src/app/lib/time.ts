export function stamp(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const t = new Date(d);
  t.setHours(0, 0, 0, 0);
  const n = new Date();
  n.setHours(0, 0, 0, 0);
  const diff = Math.round((n.getTime() - t.getTime()) / 86400000);
  let h = d.getHours();
  const ap = h >= 12 ? "PM" : "AM";
  h = h % 12 || 12;
  const time = h + ":" + String(d.getMinutes()).padStart(2, "0") + " " + ap;
  if (diff <= 0) return "Today at " + time;
  if (diff === 1) return "Yesterday at " + time;
  if (diff < 7) return d.toLocaleDateString("en-US", { weekday: "long" }) + " at " + time;
  return d.toLocaleDateString("en-US") + " " + time;
}
