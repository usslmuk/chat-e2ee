export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    const { startSweeper, prewarm } = await import("./app/api/lib/db");
    prewarm();
    startSweeper();
  }
}