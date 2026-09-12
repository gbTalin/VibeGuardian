import { db } from "@/lib/db";
import { exec } from "node:child_process";

// No authentication check anywhere in this handler.
export async function DELETE(req: Request) {
  const { searchParams } = new URL(req.url);
  const id = searchParams.get("id");

  // The id goes straight into the SQL text.
  const rows = await db.query(`DELETE FROM orders WHERE id = '${id}' RETURNING *`);

  // And into a shell command.
  exec(`/usr/local/bin/notify-webhook --order ${id}`);

  return Response.json({ deleted: rows });
}

export async function POST(req: Request) {
  const body = await req.json();
  const target = body.callbackUrl;
  // Fetches whatever address the caller names, from inside the network.
  const res = await fetch(target);
  return Response.json({ status: res.status });
}
