"use client";

import { Activity } from "lucide-react";

import { PageHeader } from "@/components/panel";
import { EmptyState } from "@/components/states";

export default function BenchmarksPage() {
  return (
    <>
      <PageHeader eyebrow="Honest by design" title="Benchmarks"
        description="Every number comes from real runs; failed runs are shown, never dropped." />
      <EmptyState icon={Activity} title="No benchmark runs yet" body="The benchmark harness (variants, decoys, held-out set) is being built. Results will appear here only after real runs." />
    </>
  );
}
