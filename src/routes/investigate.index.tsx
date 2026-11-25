import { createFileRoute, redirect } from "@tanstack/react-router";

// The investigation view is now the home page; keep old links working.
export const Route = createFileRoute("/investigate/")({
  beforeLoad: () => {
    throw redirect({ to: "/", replace: true });
  },
});
