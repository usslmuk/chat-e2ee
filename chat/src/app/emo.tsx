"use client";
import Picker from "@emoji-mart/react";
import data from "@emoji-mart/data";

export default function EmoPicker({ onPick }: { onPick: (native: string) => void }) {
  return (
    <Picker
      data={data}
      theme="dark"
      previewPosition="none"
      maxFrequentRows={0}
      perLine={9}
      autoFocus={false}
      onEmojiSelect={(e: any) => onPick(String(e.native))}
    />
  );
}
